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
- `../../datasets/lab30-shop/score_all_v2.json` — v2 评分与漏检诊断
- `../../docs/lab30-closure-run.md` — 七轮完整记录

## 定稿说明

用户选择以第七轮结果定稿：流程闭环（挖掘 → POC → 终审报告 → 评分）已达成；
检出 TP 22 / F1 0.830 低于归档 26 TP / 0.9286（归档模型为 deepseek-chat）。
差距为探索深度差异，不是流程中断，未在本轮进一步调整模型或完成策略。
