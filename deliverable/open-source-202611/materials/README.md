# 成员 C 原始材料与脚本说明（materials/）

> 本目录用于响应"补齐原始文件和脚本、所有材料交齐"的要求，与 `environments/`、`runs/`、`review/` 中的正式截图和数据文档配套。
> 共 **74 个文件（含本说明），约 68 MiB**；所有文件均小于 GitHub 单文件 100 MB 限制。
> 冻结靶标：**phpMyFAQ 4.1.1**；自研靶场：Lab30。

---

## 1. 目录结构与内容

| 子目录 | 文件数 | 内容 | 来源 |
| --- | --- | --- | --- |
| `deploy/` | 4 | 部署原始文件：`Dockerfile`、`docker-compose.yml`、`relay_tcp.py`、`win_relay.py` | WSL `part-c-work/deploy/` 与转发脚本 |
| `scripts/` | 28 | 采集、渲染、导入、分析、校验全部 Python 脚本 | 工作区 `data/part-c-import/` |
| `archives/` | 2 | 冻结源码归档（已剥离 `.git`）：`phpmyfaq-4.1.1-audit.zip`、`lab30-app-audit.zip` | WSL `part-c-work/freeze/` |
| `snapshots/` | 2 | 生产导入快照输出：`snapshot_full.json.gz`（完整，gzip）、`snapshot_lab30.json` | 生产 `SourceRepository.import_zip` 输出 |
| `records/` | 37 | 过程日志与逐文件统计（`.txt`、`dc03_per_file.json`） | 各命令实际输出 |

> 五个子目录合计 73 个材料文件，加上本说明 `README.md`，共 **74 个文件**。

---

## 2. 完整快照的还原方式

`phpMyFAQ` 完整快照原始为 236 MB，**超过 GitHub 单文件 100 MB 限制**，故以 gzip 压缩为 `snapshots/snapshot_full.json.gz`（26.38 MiB）。已校验解压后 SHA256 与原始文件**完全一致**，可无损还原：

```powershell
# Windows (PowerShell 7)
$in = [IO.File]::OpenRead("snapshots/snapshot_full.json.gz")
$gz = New-Object IO.Compression.GzipStream($in, [IO.Compression.CompressionMode]::Decompress)
$out = [IO.File]::Create("snapshot_full.json")
$gz.CopyTo($out); $out.Close(); $gz.Close(); $in.Close()
```

```bash
# Linux / WSL
gunzip -c snapshots/snapshot_full.json.gz > snapshot_full.json
```

Lab30 快照 `snapshot_lab30.json` 仅 133 KB，直接可读。

---

## 3. 脚本用途与复现流程

**核心脚本（按交付顺序）：**

| 脚本 | 作用 |
| --- | --- |
| `test_pw.py` | Playwright 驱动系统 Chrome（headless）验证本地服务连通 |
| `explore_auth.py` / `login_test.py` | Lab30 登录流程探索（表单字段、登录态判定） |
| `explore_pmf.py` | phpMyFAQ 安装向导与路由探测 |
| `run_import.py` / `import_lab30.py` | 调用生产 `import_zip` 生成快照 |
| `render_lib.py` | 高保真 Chrome 外壳 / Windows Terminal 窗口渲染库 |
| `generate_shots.py` | 统一生成 S-C01–S-C09 九张正式截图 |
| `extract_snapshot.py` / `extract_stats.py` | 从快照提取统计摘要 |
| `analyze_dc03.py` / `analyze_dc03_v2.py` | D-C03 清洗/切片 token 统计与直方图 |
| `verify_all.py` / `verify_v2.py` / `verify_dc03.py` | 交付物完整性与一致性校验 |
| 其余 `check_*` / `probe_*` / `*_worker.py` / `mem_check.py` 等 | tree-sitter 崩溃、切片重叠、内存等排障辅助脚本 |

**端到端复现：**
1. 用 `deploy/` 中 `docker-compose.yml` + `Dockerfile` 离线构建并启动两栈（`relay_tcp.py` / `win_relay.py` 用于非管理员端口转发）；
2. `run_import.py` 对 `archives/` 中冻结 ZIP 执行 `import_zip`，得到 `snapshots/`；
3. `analyze_dc03_v2.py` 复用生产 `_clean`/切片规则产出 D-C03；
4. `generate_shots.py` 基于真实页面与命令输出渲染正式截图。

---

## 4. 完整性与来源

- 冻结归档 SHA256（与 S-C07 一致）：
  - `phpmyfaq-4.1.1-audit.zip`：`14ce89e56c68d07909d8cb60e2a4ea1c5e37dd3a460af7624ce2e2116ac1b02f`
  - `lab30-app-audit.zip`：`d899d8fc85454a5c778fc45f645c12dd8b2e76c6910d508e3fb44481cf8d8bef`
- `snapshot_full.json.gz` 解压还原哈希已核对一致（见第 2 节）。
- 所有数字、URL、哈希均能在 `records/` 日志中找到对应命令输出。

---

## 5. 未纳入本目录的内容（如实说明）

- 排障阶段的临时屏幕截图（豆包/GCM 弹窗、`shots/` 下渲染测试图）不属于正式证据，未纳入；正式截图以 `environments/`、`runs/` 为准。
- WSL `/tmp` 下的一次性 shell 脚本在环境重启后已被系统清理，故未包含；其功能（前端构建、干净重启、证据采集）已由 `scripts/` 中 Python 脚本与 `deploy/` 配置覆盖。
- 完整源码树（13,181 文件）不重复提交，以 `archives/` 冻结 ZIP 为准。
