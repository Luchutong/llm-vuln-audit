# CVSS 3.1 基础评分

审计结果采用“指标与依据提取 → 宿主验证 → 确定性计算 → 项目人工修订”的流程。模型提供 AV、AC、PR、UI、S、C、I、A 八项基础指标，宿主生成标准向量、基础分和等级。模型自填的旧 `severity`、数字分数均不能覆盖计算结果。

评级为：低危 0.1–3.9、中危 4.0–6.9、高危 7.0–8.9、严重 9.0–10.0。0.0 单独显示“无基础影响”，不从漏洞列表移除；缺少有效指标显示“待评分”。首版只使用 Base Score，未独立评估时序、部署环境或业务风险。

公式、Scope/PR 权重和 Roundup 遵循 [FIRST CVSS 3.1 规范](https://www.first.org/cvss/v3.1/specification-document)。运行时与离线评价共同使用 `backend/audit/cvss31.py`；`scripts/cvss31.py` 保留旧导入路径，离线评价只需 Python 标准库，不需要加载模型服务。

## 自动指标与证据

每条 worker 漏洞输出可包含 `cvss_input`：

```json
{
  "AV": {
    "value": "N",
    "rationale": "请求参数通过 HTTP 入口到达危险操作。",
    "evidence": [{"path":"public/index.php","start_line":1,"end_line":8}]
  }
}
```

实际评分须填齐八项。每项允许的值：AV=N/A/L/P，AC=L/H，PR=N/L/H，UI=N/R，S=U/C，C/I/A=N/L/H。未知使用 `null` 并说明缺失信息，基础指标不接受 X。

自动评分的引用必须属于实际快照、行号有效且处于该 worker 真正读过的行窗口；每项必须有理由与有效引用。格式错误、越界、未读引用或缺少指标时，保存原漏洞并标为待补充，不额外循环调用模型。评分计算不读取靶场答案，不按照漏洞类型固定分数，不将 POC 成败直接换算为等级。

## 输出与状态

运行发现、项目台账、列表、详情及导出增加：

- `cvss`：有效评分对象或 `null`。包含 `version:"3.1"`、`score_basis:"Base"`、`metrics`、`base_vector`、`base_score`、`severity`。
- `cvss_assessment`：`status`、`source`、独立 `assessment_revision`、适用的 `conclusion_revision`、`engine_version`、逐项 `metric_details`、`issues`、来源 `run_id/snapshot_id` 与时间。
- `legacy_severity`：原文字等级，历史展示使用，不反推数值。

`status` 为 `scored`、`needs_information`、`legacy_unrated`，历史中不适用的评分显示 `stale`，并保留其当时数值供追溯。当前记录只有 scored 的有效 `cvss` 非空；未评分时有效 severity 为 unknown。0.0 的有效 severity 为 none。

评分状态、引用校验、自动验证、结论处置彼此独立。待评分和 0.0 不会被误归为排查记录，也不单独改变漏洞检出或目标达成规则。

## 人工修订

进入独立“漏洞详情”，点击“修订 CVSS 指标”，填写八项指标、判断依据和修订原因。可以保留或添加当前证据来源的源码引用，或明确标记人工假设。先预览，再保存项目评分。前端只呈现后端计算结果。

接口：

| 方法与路径 | 行为 |
| --- | --- |
| `POST /api/project-findings/{id}/cvss/preview` | 无写入计算预览 |
| `PUT /api/project-findings/{id}/cvss` | 重算并保存项目评分，追加历史 |
| `GET /api/project-findings/{id}/cvss-history?offset=0&limit=25` | 分页历史，limit 最大100 |

预览/保存请求均含 `metrics`（与 cvss_input 同形）、`reason`（3–2000字符）、`expected_revision`（结论版本）与 `expected_assessment_revision`（评分版本，历史未评分可为0）。人工假设须在对应项设置 `assumption:true`，清空源码引用并写明判断理由；其依据明确标记为人工假设，不冒充自动取证。

字段不完整、非法值、引用失效返回422；对象不存在返回404；版本已变化返回409。409后保留草稿，刷新比较最新结论与评分，再基于当前版本重新预览。提交和保存均不调用模型。

## 版本、继承与报告

- 项目评分历史独立于漏洞结论版本。单纯改指标、分数不会新增漏洞、制造更正结论或让仍适用的 POC 验证失效。
- 人工评分绑定当前结论版本；同一源码的重新打包或重发现保留适用人工评分，单次任务仍保存自己当时的自动评分。
- 证据、危险操作、传播路径、防护或攻击前提实质变化后，项目结论升级；旧评分留在历史并标为不再适用，新结论使用新自动评分或待评分。
- 删除来源任务不删除项目评分历史；已不存在的来源明确显示不可用。
- 宿主最终摘要冻结运行当时的评分，人工修订只影响项目当前评级。Markdown、JSON 与证据包保留分数、向量、依据和评分来源；此前结论展示其当时评分。
- 列表支持 `severity=none|unknown|low|medium|high|critical` 和 `cvss_status=scored|needs_information|legacy_unrated|stale`。状态和分页保存在 hash URL。

## 升级与回归

部署升级时先停止旧审计服务。首次打开带旧发现的数据库、且尚无 CVSS 列时，Store 用 SQLite backup 在数据库旁创建权限0600的 `*.pre-cvss31-*.bak`，然后在事务中添加字段并迁移旧等级。迁移重复执行不会补造分数或覆盖 POC 验证。已有冻结报告不重写。

需要回滚时，停止服务并使用对应备份恢复数据库；不要将仅支持旧字段的代码与已迁移的数据混用。没有 CVSS 输入的旧任务仍可继续保存发现，显示待评分。

```bash
cd backend
uv run --extra dev --frozen pytest tests/ -q
cd ../frontend
npm test
npm run build
cd ..
uv run --with playwright python scripts/ui_cvss_smoke.py http://127.0.0.1:5173 --screenshots .run/screenshots-cvss
```

浏览器验收拦截全部 API，只操作内存数据。覆盖预览、失败重试、版本冲突、重复点击、评分历史、0.0、待评分、历史等级、URL恢复、四种屏宽与深浅主题。

离线评价使用 `--check-severity --check-cvss`，未评分计为缺失，不计为0分或非法向量。`cvss_evaluation.scoring_coverage` 的分母为匹配真值的发现数，MAE和一致率仅对具有有效可比分数的命中计算，需同时阅读缺失与非法计数。
