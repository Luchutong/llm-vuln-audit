# 全量 Lab30 审计指标汇总（由 score_all.json 与 /api/runs 自动生成）

> 生成方式：仓库自带 v2 评分脚本输出 `score_all.json`，本文件由统计脚本直接读取生成，无手工誊写。

## 1. 总览对比

| 指标 | 第 1 次 (b2c46d27) | 第 2 次 (b857d53e) |
|---|---:|---:|
| 真阳性 TP | 26 | 9 |
| 假阳性 FP | 0 | 1 |
| 漏报 FN | 4 | 21 |
| 精确率 Precision | 1.0000 | 0.9000 |
| 召回率 Recall | 0.8667 | 0.3000 |
| F1 | 0.9286 | 0.4500 |

- **第 1 次全量审计**：run `b2c46d270da6450e901354f68992f942`，状态 `failed`，2026-10-26T16:36:21.914922+00:00 → 2026-10-26T16:43:59.652325+00:00，模型 `deepseek-chat`，usage={"requests": 201, "tool_calls": 309, "input_tokens": 560981, "output_tokens": 54468}
  - 终态错误：`ValueError: Planner situation ceiling cannot hold the required closure facts`
  - 文字等级：16/26 正确，准确率 0.6154
  - CVSS：23 条可评分（覆盖率 0.8846，缺报 3 条），分数 MAE=1.2870，分数准确率=0.2174，向量准确率=0.2174
- **第 2 次全量审计（复现/对照）**：run `b857d53e39ac4dc28fc93ff93ec9aab5`，状态 `failed`，2026-10-26T16:46:57.175602+00:00 → 2026-10-26T16:50:30.243391+00:00，模型 `deepseek-chat`，usage={"requests": 93, "tool_calls": 108, "input_tokens": 627852, "output_tokens": 33956}
  - 终态错误：`ValueError: Planner situation ceiling cannot hold the required closure facts`
  - 文字等级：5/9 正确，准确率 0.5556
  - CVSS：9 条可评分（覆盖率 1.0000，缺报 0 条），分数 MAE=0.8556，分数准确率=0.3333，向量准确率=0.3333

## 2. 第 1 次（主结果）漏洞类别覆盖（22 类 / 30 项真值）

| 漏洞类别 | 真值数 | 命中数 | 漏报真值 ID |
|---|---:|---:|---|
| sqli | 3 | 3 | — |
| xss_r | 2 | 2 | — |
| command_injection | 2 | 1 | 24 |
| path_traversal | 1 | 1 | — |
| lfi | 1 | 1 | — |
| rfi | 1 | 1 | — |
| code_execution | 2 | 2 | — |
| open_redirect | 1 | 1 | — |
| info_disclosure | 1 | 0 | 09 |
| weak_crypto | 1 | 1 | — |
| xss_s | 1 | 1 | — |
| ssrf | 1 | 1 | — |
| xxe | 1 | 1 | — |
| csrf | 1 | 0 | 14 |
| insecure_deserialization | 2 | 2 | — |
| idor | 1 | 1 | — |
| auth_bypass | 3 | 3 | — |
| price_manipulation | 1 | 1 | — |
| race_condition | 1 | 1 | — |
| session_fixation | 1 | 1 | — |
| weak_type_comparison | 1 | 0 | 22 |
| mass_assignment | 1 | 1 | — |

## 3. 第 1 次全量审计漏报明细（FN=4）

- 真值 09 · 数据库诊断异常与堆栈信息泄露 · 位置：app/public/ops/database.php:3
- 真值 14 · 邮箱设置跨站请求伪造 · 位置：app/public/account/settings.php:5
- 真值 22 · 会员兑换码弱类型比较绕过 · 位置：app/public/account/redeem.php:5
- 真值 24 · 主机巡检跨文件命令注入 · 位置：app/public/ops/batch-check.php:2；app/src/host_check.php:2

## 4. 第 2 次全量审计（复现/对照）漏报明细（FN=21）

- 真值 02 · 到店欢迎反射型 XSS · 位置：app/public/catalog/greeting.php:3
- 真值 03 · 网络诊断命令注入 · 位置：app/public/ops/ping.php:2
- 真值 05 · 内容中心本地文件包含 · 位置：app/public/content/page.php:3
- 真值 06 · 远程模板预览远程文件包含 · 位置：app/public/ops/template-preview.php:3
- 真值 07 · 运营公式动态函数调用代码执行 · 位置：app/public/ops/formula.php:3
- 真值 08 · 继续访问开放重定向 · 位置：app/public/auth/continue.php:3
- 真值 09 · 数据库诊断异常与堆栈信息泄露 · 位置：app/public/ops/database.php:3
- 真值 10 · 使用 MD5 存储密码 · 位置：app/public/auth/register.php:8；app/src/setup.php:17
- 真值 11 · 在线留言存储型 XSS · 位置：app/public/support/messages.php:5
- 真值 12 · 链接预览服务端请求伪造 · 位置：app/public/ops/url-preview.php:3
- 真值 13 · 合作方配置导入 XXE · 位置：app/public/ops/xml-import.php:3
- 真值 17 · 人员管理信任客户端角色 Cookie 权限绕过 · 位置：app/public/ops/users.php:2
- 真值 18 · 维护接口信任请求头认证绕过 · 位置：app/public/ops/maintenance.php:3
- 真值 19 · 下单信任客户端单价金额篡改 · 位置：app/public/orders/create.php:3；app/public/orders/create.php:5
- 真值 20 · 提现竞争条件重复支付 · 位置：app/public/wallet/withdraw.php:3；app/public/wallet/withdraw.php:7
- 真值 21 · 会话固定 · 位置：app/src/bootstrap.php:13；app/public/auth/login.php:8
- 真值 24 · 主机巡检跨文件命令注入 · 位置：app/public/ops/batch-check.php:2；app/src/host_check.php:2
- 真值 25 · 个人主页 HTML 属性注入型 XSS · 位置：app/public/account/profile.php:3
- 真值 27 · 任务导入反序列化链命令执行 · 位置：app/public/ops/jobs.php:3；app/src/dispatch_job.php:4
- 真值 29 · 营销排版模板表达式执行 · 位置：app/public/ops/template-render.php:3
- 真值 30 · 会员资料批量赋值敏感字段修改 · 位置：app/public/account/update.php:4；app/public/account/update.php:6

## 5. 第 2 次全量审计（复现/对照）误报明细（FP=1）

- support/download.php file 参数路径遍历，可读取任意可读文件
