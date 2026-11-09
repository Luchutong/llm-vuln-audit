# 原始材料（只读归档）

> 本目录是成员 B 截图的**原始数据**，全部由运行目录 `.run/` 直接复制，未做任何数值修改。
> 校验方式：`sha256sum <文件>` 与下表前 16 位比对（完整值见文末）。

## 1. 清单

| 文件 | 体积 | 内容 | 生成来源 | sha256（前 16 位） |
| --- | --- | --- | --- | --- |
| `raw/experiments/exp_c4b1374b9aae4707.json` | 2.4 MB | P20 实验完整存档（3 策略 × 3 轮 = 9 试次） | `POST /api/prompt-experiments`（protocol `lab30-full-v2`），结束后 `GET /api/prompt-experiments/c4b1374b9aae4707` 导出 | `9d4519464a29ed0b…` |
| `raw/scoring/score_a403cb8c9efd48cfbba31337c5129842.json` | 102.3 KB | run `a403cb8c` 评分明细（30 真值 / 20 结论） | `backend/.venv/bin/python scripts/score_dataset.py --protocol lab30-v2 --run a403cb8c…` | `27df4fdf0b968cad…` |
| `raw/scoring/score_a403cb8c9efd48cfbba31337c5129842.html` | 7.1 KB | 同一评分的 HTML 渲染页（S-B11 截图的数据源页面） | `python scripts/vm_gap_shots.py b11 a403cb8c…` 导出 `.run/score_<run>.html` | `24144f970291e1ba…` |
| `raw/runs/metrics_08860008deed4639b6ddf5b90671d9c7.json` | 8.6 MB | run `08860008` 指标导出（bundle / report / event_log） | `GET /api/runs/08860008…/metrics` | `2498bf5fcbc3cc94…` |
| `raw/runs/metrics_fb54bc3c054f46aaa6e3c531961f893c.json` | 4.5 MB | run `fb54bc3c` 指标导出（bundle / report / event_log） | `GET /api/runs/fb54bc3c…/metrics` | `c486d174e95801a5…` |
| `raw/runs/last_experiment.json` | 0.1 KB | 最近一次实验指针（id + 时间戳） | 截图脚本写入 `.run/last_experiment.json` | `e8bf2fe179f168c5…` |
| `raw/runs/last_gap_run.json` | 0.2 KB | 最近一次缺口审计 run 指针（run / project / snapshot） | `vm_gap_shots.py b10-start` 写入 | `9cdc2fcc309bb866…` |
| `raw/runs/last_real_run.json` | 0.2 KB | 最近一次真实审计 run 指针 | `vm_real_run.py run` 写入 | `7c09fd0d4d0deaee…` |

## 2. 与数据表的对应关系

| 交付物 | 原始文件 | 关键数值（核对点） |
| --- | --- | --- |
| D-B01 / S-B08 | `experiments/exp_c4b1374b9aae4707.json` | 9 试次、3 变体（`worker-w0-v1` / `w1` / `w2`）、`preliminary=false`；三策略 F1 = 61.77 / 62.23 / 57.70% |
| D-B04 / S-B11 | `scoring/score_a403cb8c…json` | `truths=30`、`findings=20`、TP 19 / D 1 / U 0 / FP 1 / FN 11、P 0.9500 / R 0.6333 / F1 0.7600，含 `class_coverage` 与 `cvss_evaluation` |
| S-B04 / S-B05 | `runs/metrics_08860008…json` | `bundle`（项目与快照）、`report`（结论与证据链）、`event_log`（任务图与阶段配额）三段原样导出 |
| S-B06 / S-B09（对照） | `runs/metrics_fb54bc3c…json` | 上一轮真实审计的同类导出，用于跨 run 对照 |

## 3. 重新生成命令

```bash
# 实验存档（需服务在线、已配置模型）
python scripts/vm_gap_shots.py b08-start          # 3 策略 × 3 轮 × 720 秒，硬上限 7200 秒

# 评分
backend/.venv/bin/python scripts/score_dataset.py --protocol lab30-v2 \
  --api http://127.0.0.1:8899 --run a403cb8c9efd48cfbba31337c5129842 \
  --out .run/score_a403cb8c9efd48cfbba31337c5129842.json

# run metrics
curl -s http://127.0.0.1:8899/api/runs/<run_id>/metrics > .run/metrics_<run_id>.json
```

## 4. 完整 sha256

```text
9d4519464a29ed0bce0ffea9edb00621107b3909f10f088be819036030e4c184  raw/experiments/exp_c4b1374b9aae4707.json
27df4fdf0b968cada7b5bcaf3a85c55926275f8f6921ae5f7d4a119e872d7db5  raw/scoring/score_a403cb8c9efd48cfbba31337c5129842.json
24144f970291e1ba17ab7e50e65d2ecbd6ef111fea2a1f266762d5a73966cb38  raw/scoring/score_a403cb8c9efd48cfbba31337c5129842.html
2498bf5fcbc3cc94bbc99ba61f126507a0243f4df8bcb99c6f28be2b6cf8a3a2  raw/runs/metrics_08860008deed4639b6ddf5b90671d9c7.json
c486d174e95801a577586817e3c8b134feea2498d11d3c45327c78884260a20e  raw/runs/metrics_fb54bc3c054f46aaa6e3c531961f893c.json
e8bf2fe179f168c5c02a04fb3a5d99c8775a43d8a04a3b2a71a3553b0cb8c60d  raw/runs/last_experiment.json
9cdc2fcc309bb8660e2813cbab2ed31b0112d608a6c24efe31ae86a5e8fbcaa2  raw/runs/last_gap_run.json
7c09fd0d4d0deaee90bcc851ce02187fd0d4ac811a07f356c7654360f43764f9  raw/runs/last_real_run.json
```
