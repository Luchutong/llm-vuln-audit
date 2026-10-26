# Lab30 多版本 Prompt 限时源码审计对比

实验：61e957070de54c0a · 状态：completed

本报告为官方清单匹配，不等同于漏洞已通过 POC 验证；不提供现实误报率或整体 Accuracy。
共同有效轮次：3/3。仅描述本靶场本次实验，不宣称统计显著。

## 冻结条件

协议：lab30-full-v2 / lab30-v2；POC：关闭。
模型：deepseek-chat；thinking：disabled。
每次 Agent 执行预算：{"responses": 24, "tools": 96, "seconds": 720}；每试次共享预算：{"responses": 256, "tools": 2048, "seconds": 720}。
正式基线：worker-w0-v1。

## 效果总览

| 版本 | TP 均值 | D 均值 | U 均值 | FN 均值 | Precision | Recall | F1 | ΔF1（百分点） | ΔRecall（百分点） |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| W0：基础审计 | 25.333 ± 0.577（n=3） | 8.667 ± 4.726（n=3） | 1.667 ± 0.577（n=3） | 4.667 ± 0.577（n=3） | 72.0% ± 10.0%（n=3） | 84.4% ± 1.9%（n=3） | 77.5% ± 6.2%（n=3） | +0.0 ± 0.000（n=3） | +0.0 ± 0.000（n=3） |
| W1：证据与防护 | 24.667 ± 0.577（n=3） | 11.333 ± 7.767（n=3） | 1.667 ± 1.155（n=3） | 5.333 ± 0.577（n=3） | 67.2% ± 13.2%（n=3） | 82.2% ± 1.9%（n=3） | 73.5% ± 8.1%（n=3） | -4.0 ± 3.682（n=3） | -2.2 ± 3.849（n=3） |
| W2：跨文件与业务前提 | 19.333 ± 8.963（n=3） | 5.000 ± 5.568（n=3） | 0.667 ± 1.155（n=3） | 10.667 ± 8.963（n=3） | 83.1% ± 15.5%（n=3） | 64.4% ± 29.9%（n=3） | 67.3% ± 18.4%（n=3） | -10.2 ± 22.377（n=3） | -20.0 ± 29.059（n=3） |

各项为逐轮均值 ± 样本标准差及有效 n；单轮标准差不可计算。Precision 无预测时未定义，不按 0 填充。
D 为仍重复主张的报告；U 为未匹配官方清单的候选，不代表已证伪。

## 逐轮记录

| 轮次 | 策略 | 试次 ID | 状态 | 有效性 | TP | D | U | FN | F1 | 停止原因 |
|---|---|---|---|---|---:|---:|---:|---:|---:|---|
| 1 | worker-w0-v1 | 5aa6fcfd0ec740dd | finished | valid | 25 | 5 | 1 | 5 | 82.0% | goal_met |
| 1 | worker-w1-v1 | 292b4ec526dd44d4 | finished | valid | 25 | 5 | 1 | 5 | 82.0% | goal_met |
| 1 | worker-w2-v1 | b29e07b764d24d05 | finished | valid | 9 | 0 | 0 | 21 | 46.2% | goal_met |
| 2 | worker-w1-v1 | 631bf55f5c334d03 | finished | valid | 25 | 20 | 1 | 5 | 65.8% | goal_met |
| 2 | worker-w2-v1 | 7752a7ef45914db9 | finished | valid | 25 | 11 | 0 | 5 | 75.8% | goal_met |
| 2 | worker-w0-v1 | dad2ef8bdc104553 | finished | valid | 25 | 14 | 2 | 5 | 70.4% | goal_met |
| 3 | worker-w2-v1 | d1227f3e504645dd | finished | valid | 24 | 4 | 2 | 6 | 80.0% | goal_met |
| 3 | worker-w0-v1 | 1eaa9935d9e44dda | finished | valid | 26 | 7 | 2 | 4 | 80.0% | goal_met |
| 3 | worker-w1-v1 | 1ecc2fa5fbdf4895 | finished | valid | 24 | 9 | 3 | 6 | 72.7% | goal_met |

## 时间政策与批次消耗

时间政策 fixed-time-v1：每试次最多 720 秒审计，完整生命周期最多 780 秒；首次批次含准备和收尾最多 7200 秒，补跑单独计时。
提前完成或先触及请求／工具上限时，以实际耗时和停止原因解释；不宣称运行满窗口。

| 批次 | 开始 | 截止 | 结束 | 完整耗时秒 | 状态 |
|---|---|---|---|---:|---|
| initial a0846a8f29bc4bc0 | 2026-10-26T17:05:39.821317+00:00 | 2026-10-26T19:05:39.821317+00:00 | 2026-10-26T18:08:07.650600+00:00 | 3747.829 | completed |

| 试次 | 执行次数 | 批次 | 审计耗时秒 | 完整耗时秒 | 已知 tokens | 停止原因 |
|---|---:|---|---:|---:|---:|---|
| 5aa6fcfd0ec740dd | 1 | initial | 400.198 | 401.384 | 1707472.000 | goal_met |
| 292b4ec526dd44d4 | 1 | initial | 375.885 | 377.044 | 1822732.000 | goal_met |
| b29e07b764d24d05 | 1 | initial | 157.139 | 158.658 | 1062474.000 | goal_met |
| 631bf55f5c334d03 | 1 | initial | 551.265 | 553.053 | 2274889.000 | goal_met |
| 7752a7ef45914db9 | 1 | initial | 381.678 | 383.524 | 1662447.000 | goal_met |
| dad2ef8bdc104553 | 1 | initial | 598.573 | 600.007 | 2292641.000 | goal_met |
| d1227f3e504645dd | 1 | initial | 406.839 | 408.307 | 1772352.000 | goal_met |
| 1eaa9935d9e44dda | 1 | initial | 414.027 | 415.683 | 1371093.000 | goal_met |
| 1ecc2fa5fbdf4895 | 1 | initial | 448.164 | 449.633 | 2257336.000 | goal_met |

## 资源与 CVSS（相同共同轮次）

| 版本 | 请求 | 工具调用 | tokens | 耗时秒 | tokens/TP | CVSS 可评分覆盖 | CVSS MAE | 等级一致率 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| W0：基础审计 | 90.000 ± 23.065（n=3） | 190.333 ± 85.734（n=3） | 1790402.000 ± 466337.558（n=3） | 472.274 ± 110.795（n=3） | 70912.955 ± 19616.714（n=3） | 70.3% ± 35.6%（n=3） | 1.345 ± 0.118（n=3） | 55.7% ± 29.4%（n=3） |
| W1：证据与防护 | 107.000 ± 19.000（n=3） | 277.667 ± 57.143（n=3） | 2118319.000 ± 256136.258（n=3） | 459.861 ± 88.432（n=3） | 85986.836 ± 11428.382（n=3） | 82.4% ± 8.5%（n=3） | 1.224 ± 0.313（n=3） | 58.0% ± 7.2%（n=3） |
| W2：跨文件与业务前提 | 75.333 ± 22.942（n=3） | 214.667 ± 46.694（n=3） | 1499091.000 ± 382093.681（n=3） | 316.771 ± 137.533（n=3） | 86132.849 ± 27886.594（n=3） | 75.4% ± 21.8%（n=3） | 1.103 ± 0.173（n=3） | 62.3% ± 23.1%（n=3） |

CVSS 单独统计，不参与挖掘 F1。各版本交集中的可评分漏洞进一步对照如下；空交集不计算 MAE。

| 轮次 | 共同可评分真值 | 策略 | CVSS MAE | 等级一致率 |
|---|---|---|---:|---:|
| 1 | 04, 08, 11, 23 | worker-w0-v1 | 1.275 | 75.0% |
| 1 | 04, 08, 11, 23 | worker-w1-v1 | 1.275 | 75.0% |
| 1 | 04, 08, 11, 23 | worker-w2-v1 | 0.000 | 100.0% |
| 2 | 01, 02, 04, 05, 07, 13, 17, 23, 26, 27, 28, 29 | worker-w0-v1 | 1.350 | 75.0% |
| 2 | 01, 02, 04, 05, 07, 13, 17, 23, 26, 27, 28, 29 | worker-w1-v1 | 1.692 | 66.7% |
| 2 | 01, 02, 04, 05, 07, 13, 17, 23, 26, 27, 28, 29 | worker-w2-v1 | 1.633 | 58.3% |
| 3 | 11, 27, 30 | worker-w0-v1 | 1.233 | 66.7% |
| 3 | 11, 27, 30 | worker-w1-v1 | 1.000 | 66.7% |
| 3 | 11, 27, 30 | worker-w2-v1 | 1.133 | 100.0% |

## 30 项命中矩阵

| 真值 | 类别 | worker-w0-v1 | worker-w1-v1 | worker-w2-v1 |
|---|---|---:|---:|---:|
| 01 商品搜索 SQL 注入 | sqli | 2/3 | 2/3 | 3/3 |
| 02 到店欢迎反射型 XSS | xss_r | 3/3 | 3/3 | 2/3 |
| 03 网络诊断命令注入 | command_injection | 3/3 | 3/3 | 2/3 |
| 04 帮助文档路径遍历读取任意文件 | path_traversal | 3/3 | 3/3 | 3/3 |
| 05 内容中心本地文件包含 | lfi | 3/3 | 2/3 | 2/3 |
| 06 远程模板预览远程文件包含 | rfi | 3/3 | 2/3 | 1/3 |
| 07 运营公式动态函数调用代码执行 | code_execution | 3/3 | 2/3 | 1/3 |
| 08 继续访问开放重定向 | open_redirect | 3/3 | 2/3 | 2/3 |
| 09 数据库诊断异常与堆栈信息泄露 | info_disclosure | 1/3 | 2/3 | 1/3 |
| 10 使用 MD5 存储密码 | weak_crypto | 1/3 | 0/3 | 0/3 |
| 11 在线留言存储型 XSS | xss_s | 2/3 | 3/3 | 3/3 |
| 12 链接预览服务端请求伪造 | ssrf | 3/3 | 3/3 | 2/3 |
| 13 合作方配置导入 XXE | xxe | 3/3 | 3/3 | 2/3 |
| 14 邮箱设置跨站请求伪造 | csrf | 0/3 | 0/3 | 0/3 |
| 15 会员备份不安全反序列化权益篡改 | insecure_deserialization | 2/3 | 2/3 | 2/3 |
| 16 订单详情越权访问（IDOR） | idor | 3/3 | 3/3 | 2/3 |
| 17 人员管理信任客户端角色 Cookie 权限绕过 | auth_bypass | 3/3 | 3/3 | 3/3 |
| 18 维护接口信任请求头认证绕过 | auth_bypass | 3/3 | 3/3 | 1/3 |
| 19 下单信任客户端单价金额篡改 | price_manipulation | 3/3 | 3/3 | 2/3 |
| 20 提现竞争条件重复支付 | race_condition | 3/3 | 2/3 | 2/3 |
| 21 会话固定 | session_fixation | 2/3 | 3/3 | 1/3 |
| 22 会员兑换码弱类型比较绕过 | weak_type_comparison | 2/3 | 3/3 | 2/3 |
| 23 会员查询跨文件 SQL 注入 | sqli | 3/3 | 3/3 | 3/3 |
| 24 主机巡检跨文件命令注入 | command_injection | 3/3 | 3/3 | 2/3 |
| 25 个人主页 HTML 属性注入型 XSS | xss_r | 1/3 | 2/3 | 3/3 |
| 26 合作方结算 JWT 未校验签名身份伪造 | auth_bypass | 3/3 | 3/3 | 2/3 |
| 27 任务导入反序列化链命令执行 | insecure_deserialization | 3/3 | 3/3 | 2/3 |
| 28 会员报表二次 SQL 注入 | sqli | 3/3 | 3/3 | 2/3 |
| 29 营销排版模板表达式执行 | code_execution | 3/3 | 2/3 | 2/3 |
| 30 会员资料批量赋值敏感字段修改 | mass_assignment | 3/3 | 3/3 | 3/3 |

## 22 类覆盖

| 类别 | worker-w0-v1 | worker-w1-v1 | worker-w2-v1 |
|---|---:|---:|---:|
| auth_bypass | 9/9（100.0%） | 9/9（100.0%） | 6/9（66.7%） |
| code_execution | 6/6（100.0%） | 4/6（66.7%） | 3/6（50.0%） |
| command_injection | 6/6（100.0%） | 6/6（100.0%） | 4/6（66.7%） |
| csrf | 0/3（0.0%） | 0/3（0.0%） | 0/3（0.0%） |
| idor | 3/3（100.0%） | 3/3（100.0%） | 2/3（66.7%） |
| info_disclosure | 1/3（33.3%） | 2/3（66.7%） | 1/3（33.3%） |
| insecure_deserialization | 5/6（83.3%） | 5/6（83.3%） | 4/6（66.7%） |
| lfi | 3/3（100.0%） | 2/3（66.7%） | 2/3（66.7%） |
| mass_assignment | 3/3（100.0%） | 3/3（100.0%） | 3/3（100.0%） |
| open_redirect | 3/3（100.0%） | 2/3（66.7%） | 2/3（66.7%） |
| path_traversal | 3/3（100.0%） | 3/3（100.0%） | 3/3（100.0%） |
| price_manipulation | 3/3（100.0%） | 3/3（100.0%） | 2/3（66.7%） |
| race_condition | 3/3（100.0%） | 2/3（66.7%） | 2/3（66.7%） |
| rfi | 3/3（100.0%） | 2/3（66.7%） | 1/3（33.3%） |
| session_fixation | 2/3（66.7%） | 3/3（100.0%） | 1/3（33.3%） |
| sqli | 8/9（88.9%） | 8/9（88.9%） | 8/9（88.9%） |
| ssrf | 3/3（100.0%） | 3/3（100.0%） | 2/3（66.7%） |
| weak_crypto | 1/3（33.3%） | 0/3（0.0%） | 0/3（0.0%） |
| weak_type_comparison | 2/3（66.7%） | 3/3（100.0%） | 2/3（66.7%） |
| xss_r | 4/6（66.7%） | 5/6（83.3%） | 5/6（83.3%） |
| xss_s | 2/3（66.7%） | 3/3（100.0%） | 3/3（100.0%） |
| xxe | 3/3（100.0%） | 3/3（100.0%） | 2/3（66.7%） |

## 配对变化与策略

- worker-w1-v1 相对基线 F1 下降 4.0 个百分点；配对数 3，样本标准差 3.682 个百分点。
  Recall 变化：-2.2 个百分点。
  - 第 1 轮：+0.0 个百分点；增检 01, 25；丢失 07, 15。
  - 第 2 轮：-4.6 个百分点；增检 09, 11, 15, 21；丢失 08, 10, 20, 25。
  - 第 3 轮：-7.3 个百分点；增检 22, 25；丢失 01, 05, 06, 29。
- worker-w2-v1 相对基线 F1 下降 10.2 个百分点；配对数 3，样本标准差 22.377 个百分点。
  Recall 变化：-20.0 个百分点。
  - 第 1 轮：-35.8 个百分点；增检 01, 25；丢失 02, 03, 05, 06, 07, 12, 13, 16, 18, 19, 20, 21, 22, 24, 26, 27, 28, 29。
  - 第 2 轮：+5.3 个百分点；增检 11, 15, 21；丢失 08, 10, 18。
  - 第 3 轮：+0.0 个百分点；增检 22, 25；丢失 06, 07, 15, 21。
  各轮变化方向不一致，不能解释为稳定提升。

### W0：基础审计

建立基础审计能力

正文 SHA-256：363cbe851df13b22b03351e2a0405bf997083b5a6921ae14426c00de1e9ca9a7

~~~~~~text
识别当前任务中由源码支持的可操作漏洞，说明影响，并准确指出根因或危险操作的位置。
~~~~~~

### W1：证据与防护

核对数据流和防护，减少缺乏依据的报告

正文 SHA-256：dcbdd66836af0f4b8f1c91953f8d5ec498643f70f21c6196e826e2e6487d9fc2

~~~~~~text
识别当前任务中由源码支持的可操作漏洞，说明影响，并准确指出根因或危险操作的位置。逐项核对攻击者输入来源、传播路径、关键操作及已有防护；说明防护是否覆盖当前输入路径，不能只凭函数名称判断。
~~~~~~

### W2：跨文件与业务前提

补充跨文件、权限与业务前提分析

正文 SHA-256：de03c5b4f85bc64c65899d3ba39f540f52c368caf1ba5d7fba579ae6ebf981d7

~~~~~~text
识别当前任务中由源码支持的可操作漏洞，说明影响，并准确指出根因或危险操作的位置。逐项核对攻击者输入来源、传播路径、关键操作及已有防护；说明防护是否覆盖当前输入路径，不能只凭函数名称判断。沿调用、包含与配置关系补读相关文件，核实身份、角色、对象权限、业务状态和触发前提；缺失事实应明确记录，不可凭空补全。
~~~~~~

## 审计与评分摘要

```json
{
  "assets": {
    "protocol": "lab30-v2",
    "truth_count": 30,
    "class_count": 22,
    "source_archive_sha256": "67fd87e9ae771d10eaa0797ef2c2af2e0fe381036cd8efe4f92b3d26eec3d36c",
    "truth_sha256": "6c215b702fa962082e21a60bf8237692da7e47cb6ef97889d212616fa708faaa",
    "truth_canonical_sha256": "8858d44304a77faadf204ac8e2c7f6b3f629bcd6434bdfcc6c5c37ddd9a75703",
    "anchors_sha256": "1bc01cf80d6326c2b683e251c3bf8c4f2df8bfa28005465d8108b0b73e0e7c7a",
    "checked_locations": 43
  },
  "code": {
    "commit": "2759ff911cd9f24fb80d9b0a7f1f50684376eee8",
    "dirty": false,
    "files": {
      "actions.py": "4b418f81dc94e1091006cefb2d000d1f376833af2ac17eacf05b4e1ceaac1971",
      "agent.py": "56fbf4f589b99e2e0e2550a79f93a70455038dd3d229edc6e440a4033416a6b2",
      "app.py": "8c61bc313bb13c608128cddeb9fd722b6927fe301f21e262a42cf22cf03a865b",
      "codemodel.py": "dda11a5cd6cd2a6019014438cca3e17637e6b5300955d031d4d072962cc2a29a",
      "comparison_results.py": "d12729b043a46f3404820dc11a24f8ce4064620cc2ba4f8f2c89d2dca0914521",
      "comparison_trial.py": "a77348552b55c8e26fc772d6866fb971c2206d887068db257e6006a78de724f3",
      "config.py": "9981cb1ba74640170012430db7b2a600f7d2f81d7bed389d508e83f5b5c76abd",
      "cvss31.py": "c830597f8aa8843f54b860064a7f45f7df4b498bdf888fc7f42d291c82e60107",
      "cvss_assessment.py": "5b0a6f5b9116bfe6bb7fdd755379a3d954d8e67bcf9278a4ababcda9b3ced00b",
      "cvss_store.py": "d31f1d7c71a84aff00bd3e852ed052559ad9830f8b3fe3366c4c7ba2e86dd4c1",
      "db.py": "72b5d4cbcb8ff7ff5cefad67b02eabfa6c0bce965fa0630542d04d1d708e12cf",
      "defence.py": "df58d2fd779e6b0156120ef6494ad8efd6b705016b9c53598b36fb26e384d587",
      "events.py": "28524011dd7f80443570bb1f58ab42dc987bd3300b86fe907c5da16e434e9ff0",
      "evidence.py": "5ed08294d6dd8dd65c1415414e45b6737bd7af669931eff65116e1c879327806",
      "execution_guards.py": "027884611729b8771ad0475d37b5fd9d17b968974091a7f9d37622c3a7c68d13",
      "execution_state.py": "cd1b09552e6141a5b15b04303f28ffa04626a030ff8c60741fda1473ff142f95",
      "executor.py": "4f6b44b229f8d3753c2932fd254798b270d36d7cadc85e5643a664cf13c2b89e",
      "finding_policy.py": "b432d8593976178bf703877276a164abc4bd8f5e9189bde02278fa1f8b4030df",
      "full_comparison.py": "d4e68818ed2eeb396ed362ba58c33f10a03ec3e62bf79f5da2b10f61c374c814",
      "health.py": "60b99aeadfc40061418dc255225eb0ae906af07810475a76d38f7cc53ef0d2c4",
      "lab_seed.py": "94ac87a1c751b8a000b91d369cb7a43692d7028e113db3ba16b0d70537a1e824",
      "metrics.py": "9becd0756f1fde653828e3cd3317a085bc7606fb3338ef25adede1f1e426ec83",
      "navigation.py": "7ea0c55bc30d3e92657a00ec58be220bd428518410c5294fe9c2939a333e80b5",
      "poc.py": "763970edac6f37f67f84270f84c5de9f726d4f687ee410b6724ee62c91cd7c30",
      "poc_agent.py": "8a0d5a82f115e4c6dd1c4b4402c9a656fd35c7baebe5d4302f1b700ab138162e",
      "poc_readiness.py": "6609ee8dd7551e04e9054eb29ea8740add8269794437e68b44bebdca03ff88ee",
      "poc_runner.py": "92c67139f7b4ee234bc1fe5c03d429faa94dbde9ff05260b3dc47113837bbafb",
      "poc_store.py": "ed953a9a4fdd4dcce12d954b45f7ec0c79190d9701d8fb8a6a99dd92f87390ef",
      "project_findings.py": "c36b1a66ce1d9d97c30d8f3f5c69d0a3dc1cb539ec2f297a424952c413d661ef",
      "projects.py": "ed5ef6e17a535a0dc46d16c448116c1406c2829541219f54cf7d030f2af5021d",
      "prompt_evaluation.py": "bc9775481449f9b4f3face6f07ecbae52f2bfdacc973d4de3255f715a53ff0b5",
      "prompt_experiments.py": "7896882597762a38632d87bc56ab08bf59961dc381aa73200165886e69111b4a",
      "prompt_variants.py": "c1b80ed8130ca30ce31d8e1bb6a06a67c1f533d5c483d65394721e138948d0ae",
      "prompts/code_agent.yaml": "51934da9e4cb408027570b38c70dc868156930c8d7ff35d50f7b0fc2859a926d",
      "prompts/code_agent_poc.yaml": "344755e4af4f1c5eaf927594af1ce0bb83e82e4d35ab35f5ab4e437133ad1d32",
      "prompts/code_agent_poc_conclude.yaml": "60a80dcad43687c9c9cca5502e8730fed2514a1b73f47aafe35e155f1d5df509",
      "prompts.py": "52bef9827ef189cef4176db23c34051042676a704102c62965fd6ee66ef38928",
      "recon.py": "d8e5de953c29751e89ef895f288441da98a655fd90f42832ece850ce0aa9c0ce",
      "report.py": "50b61ddf271516f12d9c58f0176753408dfa94aa44a85d4e649af2100b564cae",
      "report_facts.py": "134039fc57dc83483c24d7936eb1c3c16c7c78a1728ff1e03cf7ae9cddd984aa",
      "runtime.py": "1d11324b569860f0c03dcb625c03f1b3a61f83d4d7d5d0d0f52c773a319d7f5b",
      "safe_encoding.py": "90cbdd9e579a377702dd5243c61aaf263e25e491c19f473fc188b91b04733c60",
      "schemas.py": "92a434804676f5fc32ee72c8077c939edec07e034675e79aaf63653d942fed32",
      "source.py": "1da9e38c4d5118402e6913800a9c0f253b57a8dd095d7473cb8c3554390a49f1",
      "tool_errors.py": "fd555b6d8b8d204e27711feaeb9b3f930b9d3f0a0ee74bff89f08d8f94b068cb",
      "toolkit.py": "ca9332abb46791ff804227f3c92bfe69cd7b298b90a16478b02ca3ff78880914",
      "worker.py": "2b1e2aa053ed3cb0f5ea7cd2f8bcb8dd9a128517b4927a8c4aef24c260cb2402",
      "worker_strategies.py": "d101cb206cd04f311ce1c07ef57e092d729cc43560c6c2e23775afed54b3de16"
    }
  },
  "actual_total_usage": {
    "requests": {
      "known_total": 817,
      "known_attempts": 9,
      "attempts": 9,
      "total": 817
    },
    "tool_calls": {
      "known_total": 2048,
      "known_attempts": 9,
      "attempts": 9,
      "total": 2048
    },
    "input_tokens": {
      "known_total": 15431510,
      "known_attempts": 9,
      "attempts": 9,
      "total": 15431510
    },
    "output_tokens": {
      "known_total": 791926,
      "known_attempts": 9,
      "attempts": 9,
      "total": 791926
    },
    "total_tokens": {
      "known_total": 16223436,
      "known_attempts": 9,
      "attempts": 9,
      "total": 16223436
    }
  },
  "batch_usage": {
    "initial": {
      "attempts": 9,
      "known_totals": {
        "wall_elapsed_seconds": {
          "known_total": 3747.293,
          "known_attempts": 9,
          "attempts": 9
        },
        "audit_elapsed_seconds": {
          "known_total": 3733.768,
          "known_attempts": 9,
          "attempts": 9
        },
        "requests": {
          "known_total": 817,
          "known_attempts": 9,
          "attempts": 9
        },
        "tool_calls": {
          "known_total": 2048,
          "known_attempts": 9,
          "attempts": 9
        },
        "total_tokens": {
          "known_total": 16223436,
          "known_attempts": 9,
          "attempts": 9
        }
      },
      "wall_elapsed_seconds": 3747.293,
      "audit_elapsed_seconds": 3733.768,
      "requests": 817,
      "tool_calls": 2048,
      "total_tokens": 16223436,
      "known_total_tokens": 16223436
    },
    "retry": {
      "attempts": 0,
      "known_totals": {
        "wall_elapsed_seconds": {
          "known_total": 0,
          "known_attempts": 0,
          "attempts": 0
        },
        "audit_elapsed_seconds": {
          "known_total": 0,
          "known_attempts": 0,
          "attempts": 0
        },
        "requests": {
          "known_total": 0,
          "known_attempts": 0,
          "attempts": 0
        },
        "tool_calls": {
          "known_total": 0,
          "known_attempts": 0,
          "attempts": 0
        },
        "total_tokens": {
          "known_total": 0,
          "known_attempts": 0,
          "attempts": 0
        }
      },
      "wall_elapsed_seconds": 0,
      "audit_elapsed_seconds": 0,
      "requests": 0,
      "tool_calls": 0,
      "total_tokens": 0,
      "known_total_tokens": 0
    }
  }
}
```
