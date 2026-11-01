# 审计执行报告

源码包：lab30-shop-1.0.0-source.zip

审计目标：审计文件上传入口，查找可被外部输入触发的任意文件写入、路径穿越或危险文件上传漏洞。

时间（Asia/Shanghai）：2026-10-31 01:04:05 至 2026-10-31 01:10:12

> 基于历史冻结事实重排版；保留当时政策、结论和完成性，未重新审计。

## 结果与完成性

本轮为阶段结果；未完成范围与限制保留如下。

执行状态：本次执行已结束

停止原因：现有源码任务和覆盖已结算，进入统一证据终审。

自动验证模式：未启用

分维度完成性：

历史未记录分维度结果；保留当时完成性，不重新推算。

## 漏洞清单

规范结论 18；终审接受 18；待终审 0；存疑或排除 0。

| 编号 | 漏洞与主位置 | CVSS 3.1 | 动态验证 | 独立终审 | 详单 |
|---|---|---|---|---|---|
| C-11 | ops/template-render.php 将 {{...}} 模板表达式交 eval 执行导致代码执行<br>lab30-shop/app/public/ops/template-render.php:3 | 8.8 / 高危 | 未动态验证 | 终审接受 | [详单](findings/C-11.md) |
| C-12 | ops/batch-check.php 与 ops/ping.php 将 GET host 直接拼进 shell_exec 导致命令注入<br>lab30-shop/app/src/host_check.php:2 | 8.8 / 高危 | 未动态验证 | 终审接受 | [详单](findings/C-12.md) |
| C-16 | ops/jobs.php 对用户 base64 数据 unserialize 触发 DispatchJob::__wakeup 命令执行<br>lab30-shop/app/public/ops/jobs.php:3 | 8.8 / 高危 | 未动态验证 | 终审接受 | [详单](findings/C-16.md) |
| C-18 | ops/formula.php 将 GET func 直接作为函数名调用，可执行任意 PHP 函数（含 system/exec）<br>lab30-shop/app/public/ops/formula.php:3 | 8.8 / 高危 | 未动态验证 | 终审接受 | [详单](findings/C-18.md) |
| C-07 | ops/template-preview.php 对 GET template 直接 include 导致任意文件包含/远程包含<br>lab30-shop/app/public/ops/template-preview.php:3 | 8.3 / 高危 | 未动态验证 | 终审接受 | [详单](findings/C-07.md) |
| C-08 | catalog/index.php 将 $_GET['q'] 直接拼接进 LIKE 查询导致 SQL 注入<br>lab30-shop/app/public/catalog/index.php:4 | 7.5 / 高危 | 未动态验证 | 终审接受 | [详单](findings/C-08.md) |
| C-01 | ops/report.php 将可用户控制的 nickname 拼接进 SQL 导致二阶 SQL 注入<br>lab30-shop/app/public/ops/report.php:3 | 7.1 / 高危 | 未动态验证 | 终审接受 | [详单](findings/C-01.md) |
| C-06 | ops/xml-import.php 开启 LIBXML_NOENT&#124;LIBXML_DTDLOAD 解析用户 XML，可 XXE 读取服务器文件并回显<br>lab30-shop/app/public/ops/xml-import.php:3 | 6.5 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-06.md) |
| C-09 | ops/users.php 用客户端 Cookie role 判定管理员，可伪造读取全部用户邮箱与角色<br>lab30-shop/app/public/ops/users.php:2 | 6.5 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-09.md) |
| C-10 | support/download.php file 参数未规范化，路径穿越读取 docs 目录外文件（如 vault）<br>lab30-shop/app/public/support/download.php:3 | 6.5 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-10.md) |
| C-15 | ops/url-preview.php 未限制封装协议，file:// 可读取任意本地文件<br>lab30-shop/app/public/ops/url-preview.php:3 | 6.5 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-15.md) |
| C-03 | catalog/greeting.php 未编码输出 $_GET['name'] 导致反射型 XSS<br>lab30-shop/app/public/catalog/greeting.php:3 | 6.1 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-03.md) |
| C-02 | support/messages.php 留言原样输出导致存储型 XSS<br>lab30-shop/app/public/support/messages.php:5 | 5.4 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-02.md) |
| C-14 | account/profile.php 将 $_GET['url'] 未编码写入 href，可注入属性/协议（开放重定向与反射型 XSS 属性逃逸）<br>lab30-shop/app/public/account/profile.php:3 | 5.4 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-14.md) |
| C-05 | content/page.php 未鉴权将 $_GET['page'] 拼入 include 路径导致本地文件包含<br>lab30-shop/app/public/content/page.php:3 | 5.3 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-05.md) |
| C-04 | auth/continue.php 将 next 参数直接放入 Location 头导致开放重定向<br>lab30-shop/app/public/auth/continue.php:3 | 4.3 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-04.md) |
| C-13 | ops/url-preview.php 未校验 URL 协议/主机，file_get_contents 可 SSRF 请求内网服务<br>lab30-shop/app/public/ops/url-preview.php:3 | 4.3 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-13.md) |
| C-17 | account/backup.php 对用户提交的 base64 备份直接 unserialize 且无类白名单（PHP 对象注入）<br>lab30-shop/app/public/account/backup.php:5 | 4.2 / 中危 | 未动态验证 | 终审接受 | [详单](findings/C-17.md) |

## 覆盖与未完成工作

应审文件、实际读取、带理由跳过、方向结算分别计数，不是安全覆盖率。

应审文件 61；实际读取 59；读取或带理由跳过后复核 61；跳过 3；待复核 0。

必做方向 2；已解决 2；明确跳过 0；未结算 0。

动态验证：当前通过 0；待验证 18；待独立动态复核 0。

明确跳过的文件（不作为安全结论）：

- lab30-shop/app/public/assets/app.js：前端静态脚本，无服务端文件写入或上传处理逻辑，与目标入口无关。
- lab30-shop/app/public/assets/products.svg：静态矢量图片资源，非可执行源码，不构成上传或写入面。
- lab30-shop/app/public/ops/index.php：宿主覆盖统计显示该 ops 入口已被 worker 读取并结算（ops-url-preview-fetch 任务覆盖 ops 目录与 index.php），无新的文件写入方向，跳过避免重复派工。

## 后续行动

暂无冻结的补证动作；修复与复测材料仍按下列检查。

- C-11：修复建议待补充；修复后复测步骤与回归条件待补充
- C-12：修复后复测步骤与回归条件待补充
- C-16：修复后复测步骤与回归条件待补充
- C-18：修复后复测步骤与回归条件待补充
- C-07：修复后复测步骤与回归条件待补充
- C-08：修复后复测步骤与回归条件待补充
- C-01：修复后复测步骤与回归条件待补充
- C-06：修复后复测步骤与回归条件待补充
- C-09：修复后复测步骤与回归条件待补充
- C-10：修复后复测步骤与回归条件待补充
- C-15：修复后复测步骤与回归条件待补充
- C-03：修复后复测步骤与回归条件待补充
- C-02：修复后复测步骤与回归条件待补充
- C-14：修复后复测步骤与回归条件待补充
- C-05：修复建议待补充；修复后复测步骤与回归条件待补充
- C-04：修复后复测步骤与回归条件待补充
- C-13：修复后复测步骤与回归条件待补充
- C-17：修复后复测步骤与回归条件待补充

## 限制与追溯

- 受阻、未执行、未读取的方向均不代表安全。
- 本次运行未同时满足完成状态、覆盖闭环与验证闭环，本报告为阶段报告。

- frozen_input：dd1aa376699fc7174edeea375f067a93a6213d909cfd65ef920ac2b18796b3dc
- facts：f5b737e2dd8d60effcc16ed87aa20494a8f7537c68eae3549725a30cf7876aca
- archive_output：4bdc0bf8cf1a47811ff6a72e81c384175c6611d110a30a27417fe267dabe70a3
- renderer：delivery-report/v1
- template：3c18ac14bdb29dd52e1c63c31fcaac52b04a69bb3dbdc81a39c8d948883e359f

漏洞详单见漏洞审计报告汇编，技术事实与原始日志见归档原件。
