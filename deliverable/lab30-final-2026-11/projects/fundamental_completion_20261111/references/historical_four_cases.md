# 四例专项契约与历史证据

来源：新闭环 `3b50dbaf45955d989aacf47162e47967` 的冻结导出；原始验证及作业见 [四例历史验证材料](四例历史验证材料.json)。此处重新整理可复核契约，不冒称成员E原批次或本次新运行。旧定稿四项均匹配，专项证据不能称为新增检出。

| 真值/入口 | 角色、初态与正常对照 | 攻击操作与实际断言 | 历史作业与状态 |
| --- | --- | --- | --- |
| #16 `orders/detail.php:2` | alice会话，读本人 id=1；返回 user_id=1 和自己的配送备注 | 同会话改 id=2；返回200、user_id=2、bob及其私有备注；不存在的3–20返回404 | operator验证，作业 `24e9f4abef2748de84d5795562c06dd4` exit 0；另有两条早期poc_agent inconclusive记录，须保留 |
| #20 `wallet/withdraw.php` | alice初始余额100，顺序单次提现1后余额99、总提现1、1条流水 | 两线程同时各提现99；两条200 paid，余额0、提现总额199、三条流水 | 正常作业 `187114cede0d48c7930cbdcf4b3e8ebd` 与并发作业 `0328dd0930d94d76ba931bd8918ba83d` exit 0；poc_agent confirmed |
| #28 `account/update.php` → `ops/report.php:3` | alice昵称原为alice，operator报表查询user_id=1，仅返回alice | alice写入 UNION 载荷，再由operator读取同一用户记录；写入成功，报表出现唯一标记，`MARKER_ROW=True`、`SECRET_LEAKED=True` | 正常 `27955077e75149ecaae646e9c4a104bb`、写入 `84b9c39a2b124066a2dbb248d737bc0c`、触发 `4bb672ce19a546aea3a220522daa53ab`、恢复 `51c94975600e44cd9d3cd3f1e1abbebd` 均exit 0；poc_agent confirmed |
| #30 `account/update.php:4` | alice登录，只改display_name；role=customer、balance=100、tier=standard | 同角色提交 role=admin、balance=999999、tier=gold；响应与后续页面显示字段改变，运营入口200 | 正常 `2b24ae19ac034543a36ce82f575cafe0`、攻击 `320134d524b3488bb5e5433aa903f667` exit 0；poc_agent confirmed |

各条完整脚本、记录时间、输入与响应以JSON为准。作业 exit 0 仅说明脚本成功执行；漏洞判定依赖各条正常/攻击观测和业务断言。除 #28 有单列恢复作业外，不能从这张表推断其他项均已独立复位或清理。E所述三份专项Prompt正文已提取在 `prompts/`，其当时注册与调用记录尚未找到。
