# Lab30 闭环审计交付（2026-10-30）

本轮为第七次真实 LLM 全流程运行，首次以 `completed` 收束。

## 关键结果

| 项 | 值 |
|---|---|
| run id | `2969bcf204cd43b5baf2683cbb0e841d` |
| 终态 | `completed`（stop `goal_met`） |
| 时间 | 2026-10-30 13:58:07Z – 14:45:26Z（2832s / 10800s） |
| 模型 | deepseek-flash |
| 覆盖复核 | 61/61，pending 0（read 59） |
| POC | 47 jobs / 24 confirmed / 1 uncertain；复位 25 次；认证失败 0 |
| 上下文 | 峰值 150,895 / 393,216 字节（38.37%）；超限 0；摘要 0 |
| 终审 | 22 批次全部处置，D=0，`failed_checks` 为空 |
| v2 评分 | TP 22 / FN 8 / FP 1 / U 1；P 0.9565、R 0.7333、F1 0.8302 |

## 文件

- `index.html` — 汇报页（本地打开；Artifact 发布需要 claude.ai 登录，本会话不可用）
- `../../datasets/lab30-shop/closure_2969bcf2.json` — 闭环验收明细
- `../../datasets/lab30-shop/report_2969bcf2.md` — 终审报告
- `scoring-result.json` — v2 评分与漏检诊断
- `../../docs/lab30-closure-run.md` — 七轮完整记录

## 定稿说明

用户选择以第七轮结果定稿：流程闭环（挖掘 → POC → 终审报告 → 评分）已达成；
检出 TP 22 / F1 0.830 低于归档 26 TP / 0.9286（归档模型为 deepseek-chat）。
差距为探索深度差异，不是流程中断，未在本轮进一步调整模型或完成策略。

## 干净检出的离线复现

在仓库根目录执行：

```bash
python3 scripts/reproduce_release.py --out /tmp/lab30-score.json
```

`findings.json` 来自该运行冻结终审的 23 条规范结论，仅保留评分所需的源码根因、定位、证据和评级，不包含凭据、适配脚本或 HTTP 会话。`reproduction-manifest.json` 固定源码 ZIP、真值、锚点、输入与归档材料哈希；脚本校验后重算 TP/D/U/FN、P/R/F1。

这是归档输入的确定性重算，不会重新执行原来的 47 次 runner 作业，也不代表新模型运行必然获得同分。原始本地数据库、模型连接密钥和所有运行事件不随 Git 发布。部署与新审计步骤见 [部署指南](../../docs/deployment-and-reproduction.md)。
