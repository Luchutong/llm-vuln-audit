# Lab30 v2 评分锚点核验说明

协议为 `lab30-v2`，绑定原始 ZIP 与未改动的 `ground_truth.json`。
`scoring_anchors_v2.json` 保存文件及规范 JSON 摘要、归档根、每行 SHA-256 和选择依据。
执行模型前必须调用 `validate_assets` 校验全部资产；不允许用模型结果反向调整锚点。

2026-10-25 已逐项读取绑定 ZIP 的源码，完成以下静态核验。行号是精确可接受的主定位，
不是整个文件或宽范围窗口；多个位置表示同一根因的等价关键位置，不代表多条真值。
原始答案不变，旧版评分也保持可用。

| ID | 根因 | v2 可接受关键定位（相对归档根） |
| --- | --- | --- |
| 01 | sqli | `app/public/catalog/index.php:4` |
| 02 | xss_r | `app/public/catalog/greeting.php:3` |
| 03 | command_injection | `app/public/ops/ping.php:2` |
| 04 | path_traversal | `app/public/support/download.php:3` |
| 05 | lfi | `app/public/content/page.php:3` |
| 06 | rfi | `app/public/ops/template-preview.php:3` |
| 07 | code_execution | `app/public/ops/formula.php:3` |
| 08 | open_redirect | `app/public/auth/continue.php:3` |
| 09 | info_disclosure | `app/public/ops/database.php:3,4` |
| 10 | weak_crypto | `app/public/auth/register.php:8`；`app/src/setup.php:17` |
| 11 | xss_s | `app/public/support/messages.php:5` |
| 12 | ssrf | `app/public/ops/url-preview.php:3` |
| 13 | xxe | `app/public/ops/xml-import.php:3` |
| 14 | csrf | `app/public/account/settings.php:5` |
| 15 | insecure_deserialization | `app/public/account/backup.php:5` |
| 16 | idor | `app/public/orders/detail.php:2` |
| 17 | auth_bypass | `app/public/ops/users.php:2` |
| 18 | auth_bypass | `app/public/ops/maintenance.php:3` |
| 19 | price_manipulation | `app/public/orders/create.php:3,5,7` |
| 20 | race_condition | `app/public/wallet/withdraw.php:4,7,8` |
| 21 | session_fixation | `app/src/bootstrap.php:13,17`；`app/public/auth/login.php:3,8` |
| 22 | weak_type_comparison | `app/public/account/redeem.php:5` |
| 23 | sqli | `app/src/member_lookup.php:3` |
| 24 | command_injection | `app/src/host_check.php:2` |
| 25 | xss_r | `app/public/account/profile.php:3` |
| 26 | auth_bypass | `app/public/partner/portal.php:2,3` |
| 27 | insecure_deserialization | `app/public/ops/jobs.php:3`；`app/src/dispatch_job.php:4` |
| 28 | sqli | `app/public/ops/report.php:3` |
| 29 | code_execution | `app/public/ops/template-render.php:3` |
| 30 | mass_assignment | `app/public/account/update.php:4,5,6` |

主要修正：23/24 的入口不是 SQL/shell 执行点；28 的资料写入不是二次 SQL 的执行点；
20 的关闭会话锁不是余额竞争根因；27 接受反序列化操作及其实际执行 gadget，类别始终为
`insecure_deserialization`；30 的预处理值绑定没有补上字段权限。08 的 CVSS 0.0 仍是应检真值。

## 正式发现与匹配

只评价本次运行当前仍主张的漏洞；排查、撤回、已标记重复、被替代版本不参加。
主定位必须使用 `primary_location: {path,line}`，根因使用 `vulnerability_type`。
宿主负责验证定位已读且属于证据。评分器只允许已冻结归档根的前缀归一化，不做任意后缀或
文件名模糊匹配；宽证据区间不能代替主定位。

按“兼容根因 + 精确关键定位”建立二分图，固定排序后取最大一对一匹配。TP 为匹配数，
D 为有匹配边的多余报告，U 为无匹配边的报告，FP=D+U，FN=30−TP。
Precision=TP/(TP+D+U)，Recall=TP/30，F1=2TP/(2TP+D+U+FN)。
零报告的 Precision 为 null，Recall/F1 为0。U 不是“已证伪发现”；没有安全负例，不提供 Accuracy/FPR。

CVSS 使用既有 CVSS 3.1 基础分计算器，与检出独立；缺失不计为0，不按评分质量挑选重复发现。
所有版本只在共同有效轮集合上求均值和样本标准差，先算每轮分数和配对变化再汇总，
不能取三轮并集、最好一轮或汇总计数。零报告 Precision 不纳入平均，显示其有效 n。

```bash
python scripts/verify_lab30_dataset.py /path/to/source.zip datasets/lab30-shop/ground_truth.json --protocol lab30-v2
python scripts/score_dataset.py --protocol lab30-v2 --findings run.json --out /tmp/lab30-v2.json
```

核验为静态源码核验，不代表执行了攻击、POC 或数据库重置。修改数据集需要升级协议并重新核验，
历史实验继续使用其冻结资产和评分，不自动重算。
