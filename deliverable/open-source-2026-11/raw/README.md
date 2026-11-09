# 原始材料（只读归档）

> 本目录是成员 B 截图的**原始数据**，全部由运行目录 `.run/` 直接复制或按同一参数重跑，未做任何数值修改。
> 校验方式：`sha256sum <文件>` 与下表前 16 位比对（完整值见文末）。

## 1. 清单（16 个文件）

| 文件 | 体积 | 内容 | 生成来源 | sha256（前 16 位） |
| --- | --- | --- | --- | --- |
| `raw/cloc/cloc_backend_2026-11-09-rerun.json` | 0.7 KB | cloc 分目录输出：backend | 同上（单目录） | `e4f0371717de20ff…` |
| `raw/cloc/cloc_frontend_src_2026-11-09-rerun.json` | 0.5 KB | cloc 分目录输出：frontend/src | 同上（单目录） | `e71ef0caec0a2670…` |
| `raw/cloc/cloc_labs_lab30_2026-11-09-rerun.json` | 1.1 KB | cloc 分目录输出：labs/lab30 | 同上（单目录） | `f2e4afaf5dbe27aa…` |
| `raw/cloc/cloc_poc_runner_2026-11-09-rerun.json` | 0.6 KB | cloc 分目录输出：poc_runner | 同上（单目录） | `927e08d84083b7f4…` |
| `raw/cloc/cloc_total_2026-11-09-rerun.json` | 1.4 KB | cloc 合计输出：五源语言 331 文件 / 75,848 行，全语言 353 / 83,769（与 D-B02 一致） | `cloc backend frontend/src labs/lab30 poc_runner --exclude-dir=… --json --quiet`（2026-11-09 重跑） | `98970be140c9a899…` |
| `raw/code-version/experiment_vs_main_13files.patch` | 137.7 KB | 实验代码（manifest 指纹版）与仓库 main（af40175）13 个差异文件的统一 diff | `diff -u` 逐文件生成，a/ = 仓库 main，b/ = 实验代码 | `8aeefe283ad4a7fa…` |
| `raw/experiments/exp_c4b1374b9aae4707.json` | 2.4 MB | P20 实验完整存档（3 策略 × 3 轮 = 9 试次） | `POST /api/prompt-experiments`（protocol `lab30-full-v2`），结束后 `GET /api/prompt-experiments/c4b1374b9aae4707` 导出 | `9d4519464a29ed0b…` |
| `raw/runs/last_experiment.json` | 0.1 KB | 最近一次实验指针（id + 时间戳） | 截图脚本写入 `.run/last_experiment.json` | `e8bf2fe179f168c5…` |
| `raw/runs/last_gap_run.json` | 0.2 KB | 最近一次缺口审计 run 指针（run / project / snapshot） | `vm_gap_shots.py b10-start` 写入 | `9cdc2fcc309bb866…` |
| `raw/runs/last_real_run.json` | 0.2 KB | 最近一次真实审计 run 指针 | `vm_real_run.py run` 写入 | `7c09fd0d4d0deaee…` |
| `raw/runs/metrics_08860008deed4639b6ddf5b90671d9c7.json` | 8.6 MB | run `08860008` 指标导出（bundle / report / event_log） | `GET /api/runs/08860008…/metrics` | `2498bf5fcbc3cc94…` |
| `raw/runs/metrics_fb54bc3c054f46aaa6e3c531961f893c.json` | 4.5 MB | run `fb54bc3c` 指标导出（bundle / report / event_log） | `GET /api/runs/fb54bc3c…/metrics` | `c486d174e95801a5…` |
| `raw/scoring/score_a403cb8c9efd48cfbba31337c5129842.html` | 7.1 KB | 同一评分的 HTML 渲染页（S-B11 截图的数据源页面） | `python scripts/vm_gap_shots.py b11 a403cb8c…` 导出 `.run/score_<run>.html` | `24144f970291e1ba…` |
| `raw/scoring/score_a403cb8c9efd48cfbba31337c5129842.json` | 102.3 KB | run `a403cb8c` 评分明细（30 真值 / 20 结论） | `backend/.venv/bin/python scripts/score_dataset.py --protocol lab30-v2 --run a403cb8c…` | `27df4fdf0b968cad…` |
| `raw/tests/npmtest_frontend_2026-11-08.log` | 29.1 KB | D-B03 前端 node:test 当次原始输出（125/125 通过） | `bash scripts/_run_tests.sh`（写入 VM `.run/npmtest_20261108.log`） | `cb50e2041f9cd63d…` |
| `raw/tests/pytest_backend_2026-11-08.log` | 11.5 KB | D-B03 后端 pytest 当次原始输出（2026-11-08 23:13 于 VM 采集） | `bash scripts/_run_tests.sh`（写入 VM `.run/pytest_20261108.log`） | `8131dd65d6bd9408…` |

## 2. 与数据表的对应关系

| 交付物 | 原始文件 | 关键数值（核对点） |
| --- | --- | --- |
| D-B01 / S-B08 | `experiments/exp_c4b1374b9aae4707.json` | 9 试次、3 变体（`worker-w0-v1` / `w1` / `w2`）、`preliminary=false`；三策略 F1 = 61.77 / 62.23 / 57.70% |
| D-B02 | `cloc/cloc_total_2026-11-09-rerun.json` | 五源语言 331 文件 / 75,848 代码行，全语言 353 / 83,769（与 D-B02 表逐项一致） |
| D-B03 | `tests/pytest_backend_2026-11-08.log` | `3 failed, 2265 passed, 1 warning in 273.42s`，`PYTEST_EXIT=1` |
| D-B03 | `tests/npmtest_frontend_2026-11-08.log` | `# pass 125 / # fail 0`，`NPM_EXIT=0` |
| D-B04 / S-B11 | `scoring/score_a403cb8c…json` | `truths=30`、`findings=20`、TP 19 / D 1 / U 0 / FP 1 / FN 11、P 0.9500 / R 0.6333 / F1 0.7600，含 `class_coverage` 与 `cvss_evaluation` |
| S-B04 / S-B05 | `runs/metrics_08860008…json` | `bundle`（项目与快照）、`report`（结论与证据链）、`event_log`（任务图与阶段配额）三段原样导出 |
| 代码版本锁定 | `code-version/experiment_vs_main_13files.patch` | 实验代码与仓库 main 的 13 个差异文件统一 diff（详见 `data/D-B05` §二） |

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

# 测试资产（D-B03）
bash scripts/_run_tests.sh                        # 写 .run/pytest_*.log 与 .run/npmtest_*.log

# 代码规模（D-B02）
cloc backend frontend/src labs/lab30 poc_runner \
  --exclude-dir=node_modules,.venv,__pycache__,dist,.pytest_cache,data,coverage,htmlcov \
  --json --quiet
```

## 4. cloc 重跑说明（如实标注）

2026-11-08 当次的 `/tmp/cloc_20261108.json` 保存在虚拟机易失目录 `/tmp`，虚拟机重启后丢失。`raw/cloc/` 下的 5 份 JSON 为 **2026-11-09 19:10 重跑**产物，重跑与当次采集完全同源：

- 同一台虚拟机、同一项目副本（`manifest.code.files` 的 83 个文件 SHA-256 指纹在两次采集间无任何变化）；
- 同一 `cloc` 版本（`/usr/bin/cloc`，1.82）与同一排除目录参数；
- 重跑合计（五源 331 / 75,848；全语言 353 / 83,769）与 D-B02 表逐项一致，可作当次口径的等价替代证据。

## 5. 完整 sha256

```text
e4f0371717de20ff40cc68da60450bb392f93786a3db063cba4c4be49b47f32e  raw/cloc/cloc_backend_2026-11-09-rerun.json
e71ef0caec0a267034c69f81e2c22127fdc4ea90b3f3f32834063ad3afe2bb05  raw/cloc/cloc_frontend_src_2026-11-09-rerun.json
f2e4afaf5dbe27aab6ff3e0d90912e0b99fd13fcd30eff78e3c64e27bd35f89f  raw/cloc/cloc_labs_lab30_2026-11-09-rerun.json
927e08d84083b7f4433443e064b9945d2eb5247c15362cee4ea12c79bb44015e  raw/cloc/cloc_poc_runner_2026-11-09-rerun.json
98970be140c9a89974c7c34b75a09de261c102ac2f4cd01eb9c69cd96d5e6b93  raw/cloc/cloc_total_2026-11-09-rerun.json
8aeefe283ad4a7fad85245846ba7fa1e59e49a448e0d814527ea0c925404a357  raw/code-version/experiment_vs_main_13files.patch
9d4519464a29ed0bce0ffea9edb00621107b3909f10f088be819036030e4c184  raw/experiments/exp_c4b1374b9aae4707.json
e8bf2fe179f168c5c02a04fb3a5d99c8775a43d8a04a3b2a71a3553b0cb8c60d  raw/runs/last_experiment.json
9cdc2fcc309bb8660e2813cbab2ed31b0112d608a6c24efe31ae86a5e8fbcaa2  raw/runs/last_gap_run.json
7c09fd0d4d0deaee90bcc851ce02187fd0d4ac811a07f356c7654360f43764f9  raw/runs/last_real_run.json
2498bf5fcbc3cc94bbc99ba61f126507a0243f4df8bcb99c6f28be2b6cf8a3a2  raw/runs/metrics_08860008deed4639b6ddf5b90671d9c7.json
c486d174e95801a577586817e3c8b134feea2498d11d3c45327c78884260a20e  raw/runs/metrics_fb54bc3c054f46aaa6e3c531961f893c.json
24144f970291e1ba17ab7e50e65d2ecbd6ef111fea2a1f266762d5a73966cb38  raw/scoring/score_a403cb8c9efd48cfbba31337c5129842.html
27df4fdf0b968cada7b5bcaf3a85c55926275f8f6921ae5f7d4a119e872d7db5  raw/scoring/score_a403cb8c9efd48cfbba31337c5129842.json
cb50e2041f9cd63def2a1f50d4c0a8e42a4a255306dfc74ab36454b73c45edb5  raw/tests/npmtest_frontend_2026-11-08.log
8131dd65d6bd9408c94c20ed54ffab45c0b23b3dee5706675850595e4c7ccace  raw/tests/pytest_backend_2026-11-08.log
```
