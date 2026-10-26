# 03 Prompt 横向比对实验（lab30-full-v2）

固定协议：策略 `worker-w0-v1`（基线）/`worker-w1-v1`/`worker-w2-v1`，各 3 轮共 9 个串行试次，
单试次 720 秒、整组墙钟 7200 秒、POC 关闭。运行后保存：

- `create_request.json` / `create_response.json`：冻结的实验契约与 experiment_id；
- `poll_progress.txt`：30 秒粒度的状态轮询记录；`state_latest.json`：最近一次完整状态；
- `comparison-*.md`：Markdown 总报告；`report.json`（或同名 json）：结构化结果；
  `comparison-*-csv.zip`：summary/trials/truth_matrix 三张 CSV；
- `final_state.json`、`summary.json`：终态与共同轮汇总。
