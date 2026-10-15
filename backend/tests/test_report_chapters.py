"""The exported report as a document: chapter outline and the honesty of 6.1/6.2.

The report is what gets handed in, and it travels without the database behind it. Two
things have to hold no matter which run produced it: the six-chapter outline stays
numbered (an omitted section silently renumbers the rest), and a unit that ran out of
exploration budget is visible as such instead of vanishing between "finished" and "failed".
"""
import io
import zipfile

from audit.metrics import summarise
from audit.report import collect_evidence, render_markdown, render_zip

RUN = {
    "id": "r" * 32,
    "snapshot_id": "s" * 32,
    "snapshot_name": "demo.zip",
    "scope": ["vuln.php", "safe.php"],
    "prompt_id": "P0",
    "prompt_label": "P0 初始版",
    "prompt_text": "# 一、审计角色\n\n四段式提示词全文。",
    "model": "test-model",
    "budgets": {"responses": 8, "tools": 16, "seconds": 300},
    "status": "completed",
    "created_at": "2026-01-01T00:00:00+00:00",
    "started_at": "2026-01-01T00:00:00+00:00",
    "finished_at": "2026-01-01T00:10:00+00:00",
    "error": None,
    "usage": {"requests": 12, "tool_calls": 9, "input_tokens": 1000, "output_tokens": 200},
}

TRUTHS = [
    {
        "file_path": "vuln.php", "category": "sqli", "vulnerable": True,
        "independently_verified": True, "verification_basis": "人工验证：正常输入返回 1 行，注入返回 5 行",
    },
    {
        "file_path": "safe.php", "category": "sqli", "vulnerable": False,
        "independently_verified": True, "verification_basis": "人工验证：参数绑定，闭合引号无效",
    },
]


def unit(unit_id, file_path, status="completed", conclusions=None, truncated=None, error=None):
    result = {"conclusions": conclusions or {}}
    if truncated:
        result["exploration_incomplete"] = truncated
    return {
        "unit_id": unit_id,
        "file_path": file_path,
        "symbol": "<top-level>",
        "status": status,
        "error": error,
        "result": result,
        "seen": [],
        "start_line": 1,
        "end_line": 10,
    }


def finding(**over):
    base = {
        "id": "f1", "unit_id": "u1", "file_path": "vuln.php", "symbol": "<top-level>",
        "fingerprint": "fp-sqli-vuln", "category": "sqli",
        "title": "SQL 注入 · <top-level>", "severity": "high",
        "summary": "输入直接拼接进查询。",
        "evidence": [{"path": "vuln.php", "start_line": 3, "end_line": 5}],
        "input_source": "$_GET['id']", "propagation": "→ $id → $query",
        "dangerous_operation": "mysqli_query", "protection": "无", "preconditions": ["已登录"],
        "missing_context": [], "poc": None, "remediation": "改用参数绑定。",
        "validation_state": "candidate", "validation_errors": [], "verdict": None,
        "verifications": [],
    }
    base.update(over)
    return base


def verification(**over):
    """A human verification record as the report reads it."""
    base = {
        "id": "v1", "created_at": "2026-01-01T00:05:00+00:00", "execution_status": "success",
        "verdict": "confirmed", "command": "php poc.php 1' OR '1'='1", "normal_observation": "1 行",
        "attack_observation": "5 行", "files": [],
    }
    base.update(over)
    return base


def bundle(units, findings=None):
    findings = findings or []
    return {
        "run": RUN,
        "units": units,
        "findings": findings,
        "attributions": [],
        "metrics": summarise(RUN, units, findings, TRUTHS),
        "snapshot": {"id": RUN["snapshot_id"], "name": "demo.zip", "files": [], "warnings": []},
        "truths": TRUTHS,
        "prompts": [],
        "rounds": {},
        "generated_at": "2026-01-01T00:10:00+00:00",
        "version": "test",
    }


def render(units, findings=None):
    return render_markdown(bundle(units, findings))


def test_the_six_chapter_outline_has_no_gaps():
    # 6.5 used to render only when there was something to attribute, which renumbered 6.6
    # and 6.7 and read as if a section were missing from the outline.
    doc = render([unit("u1", "vuln.php"), unit("u2", "safe.php")])
    for heading in (
        "## 1. ", "## 2. ", "## 3. ", "## 4. ", "## 5. ", "## 6. ",
        "### 6.1 ", "### 6.2 ", "### 6.3 ", "### 6.4 ", "### 6.5 ", "### 6.6 ", "### 6.7 ",
    ):
        assert f"\n{heading}" in doc, f"missing {heading}"
    assert [line for line in doc.splitlines() if line.startswith("### 6.")] == [
        "### 6.1 错误与未决样本（不视为阴性）",
        "### 6.2 统计口径",
        "### 6.3 候选漏洞与验证依据",
        "### 6.4 引用全部无法核实的候选（保留记录，不计入候选）",
        "### 6.5 误报/漏报归因",
        "### 6.6 真值样本集",
        "### 6.7 交付物",
    ]


def test_a_failed_unit_is_listed_as_unfinished():
    doc = render([unit("u1", "vuln.php", status="failed", error="TimeoutError: 收尾超时")])
    unfinished = doc.split("### 6.1", 1)[1].split("### 6.2", 1)[0]
    assert "| `u1" in unfinished and "failed" in unfinished
    assert "TimeoutError" in unfinished
    assert "探索阶段被截断" not in unfinished  # nothing was truncated in this run


def test_a_truncated_unit_is_shown_with_the_verdict_it_still_gave():
    # The unit finished, so it is not in the unfinished table — but a reader weighing a
    # "no_candidate" needs to know the model was cut off before it stopped reading.
    doc = render([unit("u1", "safe.php", conclusions={"sqli": "no_candidate"}, truncated="budget")])
    section = doc.split("### 6.1", 1)[1].split("### 6.2", 1)[0]
    assert "另有 1 个单元在探索阶段被截断" in section
    assert "| `u1" in section and "budget" in section and "SQL 注入=no_candidate" in section
    assert "**仍计入统计**" in section


def test_section_6_4_distinguishes_the_two_ways_it_can_be_empty():
    # "No candidate was thrown out" and "there were no candidates" are different facts. A
    # bare heading would let both read as "the citation check found nothing wrong".
    nothing_produced = render([unit("u1", "safe.php", conclusions={"sqli": "no_candidate"})])
    assert "本次运行未产生候选漏洞，因而也没有被剔除的候选。" in nothing_produced

    all_clean = render([unit("u1", "vuln.php")], [finding()])
    section = all_clean.split("### 6.4", 1)[1].split("### 6.5", 1)[0]
    assert "每条候选都至少有一条引用通过了核验" in section


def test_the_statistics_section_says_why_truncated_units_still_count():
    # Otherwise the number in 6.1 and the matrix in 6.2 look like they disagree.
    doc = render([unit("u1", "safe.php", conclusions={"sqli": "no_candidate"}, truncated="budget")])
    section = doc.split("### 6.2", 1)[1].split("### 6.3", 1)[0]
    assert "被截断但随后被强制收尾并给出结论的单元（本次 1 个，见 6.1）**计入矩阵**" in section
    # ...and the one sample it did resolve is a genuine true negative, so the matrix is real.
    assert "混淆矩阵：TP=0、FP=0、FN=0、TN=1。" in section


def test_chapter_5_names_which_categories_ran_out_of_settlement_clock():
    # The README's "模型输出不稳定" is the abstract version of this. The report has the unit's
    # own error string, so it can say which unit and which category, and quote the ceilings
    # that were hit — a reader can then go and check those units instead of taking it on faith.
    doc = render([
        unit("u1", "vuln.php", status="incomplete",
             error="UnexpectedModelBehavior: Exceeded maximum output retries (1) | "
                   "收尾阶段 xss_r 判定失败: TimeoutError after 200s (ceiling 200s, 90s per request)"),
    ])
    section = doc.split("## 5. ", 1)[1].split("## 6. ", 1)[0]
    assert "**收尾阶段未能作答**" in section
    assert "`vuln.php`（反射型 XSS）" in section
    assert "200 秒" in section and "90 秒" in section


def test_chapter_5_does_not_invent_a_settlement_failure():
    # A unit can fail for reasons that have nothing to do with the settlement clock; the
    # paragraph has to be absent then, not printed with an empty list of units.
    doc = render([unit("u1", "vuln.php", status="failed", error="TimeoutError: 收尾超时")])
    assert "收尾阶段未能作答" not in doc


def test_the_evidence_bundle_carries_both_kinds_of_evidence(tmp_path):
    # The bundle is handed to someone who has neither the database nor the server. A reader
    # who gets verification notes for a script that is not in the archive cannot check
    # anything, so the model's POC has to travel with the human's attachment.
    (tmp_path / "v1-log.txt").write_bytes(b"attack output: 5 rows")
    poc = {"filename": "poc_sqli.php", "script": "<?php echo 1;", "language": "php"}
    published = finding(
        poc=poc,
        verifications=[verification(files=[{"stored": "v1-log.txt", "url": "/api/evidence/v1-log.txt"}])],
    )
    made = bundle([unit("u1", "vuln.php")], [published])

    data = render_zip(made, collect_evidence(made, tmp_path))
    archive = zipfile.ZipFile(io.BytesIO(data))
    names = archive.namelist()
    assert "report.md" in names and "result.json" in names
    assert "evidence/poc_f1_poc_sqli.php" in names
    assert "evidence/v1-log.txt" in names
    assert "evidence/README.txt" in names
    assert archive.read("evidence/v1-log.txt") == b"attack output: 5 rows"
    # ...and the copy inside the archive is the same document the endpoint serves, not a
    # second rendering that could drift from it.
    assert archive.read("report.md").decode() == render_markdown(made)


def test_the_original_poc_is_named_the_same_in_the_report_and_the_archive(tmp_path):
    # The adapted script had this test already; the model's own script did not, and the
    # report printed only its bare filename while the archive stored it under a
    # finding-prefixed one — four POCs travelled in the bundle that no reader could locate.
    made = bundle(
        [unit("u1", "vuln.php")],
        [finding(id="abcdef1234", poc={"filename": "sqli_low_poc.php", "script": "<?php echo 1;"})],
    )
    files = dict(collect_evidence(made, tmp_path))
    doc = render_markdown(made)
    assert "evidence/poc_abcdef12_sqli_low_poc.php" in doc
    assert files["poc_abcdef12_sqli_low_poc.php"] == b"<?php echo 1;"


def test_a_rejected_findings_poc_is_still_collected(tmp_path):
    # 6.4 keeps findings whose citations could not be verified. Their scripts do not count as
    # candidates, but they are the first thing a reviewer wants when questioning the
    # rejection, so they belong in the archive rather than only in the server's database.
    discarded = finding(
        validation_state="invalid_evidence",
        validation_errors=["行号 3-5 不属于当前快照"],
        poc={"filename": "poc_xss.html", "script": "<script>alert(1)</script>"},
    )
    made = bundle([unit("u1", "vuln.php")], [discarded])
    files = dict(collect_evidence(made, tmp_path))
    assert "poc_f1_poc_xss.html" in files
    assert files["poc_f1_poc_xss.html"] == b"<script>alert(1)</script>"


def test_an_attachment_named_like_a_path_cannot_escape_the_evidence_directory(tmp_path):
    # The stored name comes back from the database, but it was derived from an upload
    # filename. Anything with a separator in it must not be able to reach outside.
    outside = tmp_path.parent / "secret.txt"
    outside.write_bytes(b"should not travel")
    escaped = finding(
        verifications=[verification(files=[{"stored": "../secret.txt"}])],
    )
    made = bundle([unit("u1", "vuln.php")], [escaped])
    assert collect_evidence(made, tmp_path) == []


def test_section_6_2_accounts_for_candidates_the_truth_set_does_not_cover():
    # 6.3 lists every candidate; 6.2 prints a matrix over truth samples. Without a line
    # connecting them, a reader with four candidates and a six-sample matrix cannot tell
    # whether the extra one was scored, ignored, or forgotten.
    units = [unit("u1", "vuln.php", conclusions={"sqli": "candidate", "xss_r": "candidate"})]
    findings = [
        finding(),
        finding(id="f2", category="xss_r", fingerprint="fp-xss-vuln", title="反射型 XSS · <top-level>"),
    ]
    doc = render(units, findings)
    section = doc.split("### 6.2", 1)[1].split("### 6.3", 1)[0]
    assert "1 个文件×类别组合落在真值样本集之外" in section
    assert "**无法判为命中或误报**" in section
    assert "| `f2" in section and "反射型 XSS" in section
    # The sqli candidate does have a truth sample, so it is scored and must not be listed.
    assert "fp-sqli-vuln" not in section


def test_a_run_whose_candidates_all_match_truth_samples_shows_no_such_table():
    doc = render([unit("u1", "vuln.php")], [finding()])
    section = doc.split("### 6.2", 1)[1].split("### 6.3", 1)[0]
    assert "0 个文件×类别组合落在真值样本集之外" in section
    assert "无法评分的原因" not in section


def test_a_verification_record_carries_its_adaptation_and_attribution():
    # The table holds the observation. The environment, the adaptation and the attribution
    # are the rest of the flow the assignment asks for, and without them the exported
    # report shows a verdict with no account of how the script got there.
    published = finding(
        poc={"filename": "poc_xss.php", "script": "<?php echo 1;"},
        verifications=[
            verification(
                id="v9", execution_status="success",
                target_version="DVWA 2.5 (a96943dc…)，security=low",
                expected_result="注入输入多出一个标记",
                browser_execution=True,
                modification_notes="原脚本的 payload 多了一个单引号，SQL 报错所以没反射。",
                modified_script="<?php echo 'adapted';",
                notes="归因：载荷脚本缺陷，不是漏洞不成立。",
                files=[{"stored": "v9-browser.txt", "url": "/api/evidence/v9-browser.txt"}],
            )
        ],
    )
    doc = render([unit("u1", "vuln.php")], [published])
    assert "第 1 条验证记录的补充说明：" in doc
    assert "目标环境：DVWA 2.5" in doc
    assert "预期结果：注入输入多出一个标记" in doc
    assert "浏览器执行证据：已提交" in doc
    assert "脚本适配与问题归因：原脚本的 payload 多了一个单引号" in doc
    assert "- 备注：归因：载荷脚本缺陷" in doc


def test_the_adapted_script_is_named_the_same_in_the_report_and_the_archive(tmp_path):
    # A report that points at a file the archive does not contain is worse than one that
    # says nothing: the reader goes looking and finds an empty shelf.
    made = bundle(
        [unit("u1", "vuln.php")],
        [
            finding(
                poc={"filename": "poc_xss.php", "script": "<?php echo 1;"},
                verifications=[verification(id="v9abcdef", modified_script="<?php echo 'adapted';")],
            )
        ],
    )
    files = dict(collect_evidence(made, tmp_path))
    doc = render_markdown(made)
    assert "evidence/v9abcdef-adapted-poc_xss.php" in doc
    assert files["v9abcdef-adapted-poc_xss.php"] == b"<?php echo 'adapted';"
    # The size printed next to the link is the size of the file in the archive, so a
    # reader comparing the two finds the same number rather than two different ones.
    assert f"{len(files['v9abcdef-adapted-poc_xss.php'])} 字节" in doc


def test_a_record_with_nothing_but_an_observation_adds_no_clutter():
    # Most records are just "ran it, saw this". Printing an empty scaffolding under them
    # would train the reader to skip the block that matters on the records that have one.
    made = bundle([unit("u1", "vuln.php")], [finding(verifications=[verification()])])
    doc = render_markdown(made)
    assert "人工验证记录" in doc
    assert "补充说明" not in doc


def test_chapter_5_does_not_claim_a_list_that_is_not_there():
    # "0 units are listed below" reads as a section that lost its table. With nothing
    # unfinished, the rule still belongs in the chapter — as a rule, not as a promise.
    doc = render([unit("u1", "vuln.php"), unit("u2", "safe.php")])
    section = doc.split("## 5. ", 1)[1].split("## 6. ", 1)[0]
    assert "未完成单元 0 个，均单列于下方" not in section
    assert "本次运行没有未完成的单元" in section


def test_section_6_5_points_at_the_poc_defects_the_matrix_cannot_show():
    # FP and FN are both zero here, so the attribution table is genuinely empty — but two
    # of the candidates needed a human to repair their POC before the vulnerability could
    # be shown. A bare "nobody wrote an attribution" line would bury that.
    repaired = verification(
        modification_notes="原脚本的 payload 多了一个单引号，SQL 报错所以没反射。",
        modified_script="<?php echo 'adapted';",
    )
    findings = [
        finding(verifications=[repaired]),
        finding(id="f2", fingerprint="fp-2", verifications=[verification(id="v2")]),
    ]
    doc = render([unit("u1", "vuln.php")], findings)
    section = doc.split("### 6.5", 1)[1].split("### 6.6", 1)[0]
    assert "2 条候选中，1 条的 POC **按原样运行无法证明漏洞成立**" in section
    assert "把「POC 没跑通」直接读成「漏洞不成立」" in section


def test_section_6_5_stays_quiet_when_every_poc_worked_as_written():
    doc = render([unit("u1", "vuln.php")], [finding(verifications=[verification()])])
    section = doc.split("### 6.5", 1)[1].split("### 6.6", 1)[0]
    assert "按原样运行无法证明漏洞成立" not in section


def test_goal_task_report_uses_goal_termination_instead_of_fixed_truth_matrix():
    """The exported artifact must not narrate a custom objective as a three-class run."""
    task_run = {
        **RUN,
        "status": "unreachable",
        "task_spec": {
            "objective": "寻找未经授权的文件读取路径。",
            "success_criteria": "保存一处带原始行号的可达读取证据。",
            "max_iterations": 2,
            "max_total_attempts": 8,
            "max_workers": 2,
            "stop_on_achieved": True,
            "require_poc": True,
        },
    }
    units = [unit("u1", "safe.php")]
    made = {
        **bundle(units),
        "run": task_run,
        "metrics": summarise(task_run, units, [], TRUTHS),
        "goals": [{
            "status": "unreachable",
            "attempts": 2,
            "max_total_attempts": 8,
            "terminal_reason": "所有已规划工作项均已完成，仍未满足验收条件",
        }],
    }
    doc = render_markdown(made)
    assert "# 项目源码目标审计报告" in doc
    assert "运行状态：不可达" in doc
    assert "寻找未经授权的文件读取路径" in doc
    assert "不套用固定 SQL 注入 / XSS / 命令注入真值矩阵" in doc
    assert "目标文本中出现的文件路径和代码标识进行稳定排序" in doc
    assert "模型的隐藏思维链" in doc
    assert "DVWA" not in doc
    assert "目标任务协调器" in doc
    assert "任务总尝试上限：8 次并由所有 worker 共享" in doc
    assert "缺少 POC 的 achieved 输出会被要求纠正，不能达成目标" in doc


def test_goal_task_report_renders_source_review_without_a_fake_execution_table():
    task_run = {
        **RUN,
        "status": "completed",
        "task_spec": {
            "objective": "梳理认证状态读取边界。",
            "success_criteria": "保存一条带原始行号的认证边界结论。",
            "max_iterations": 2,
            "max_total_attempts": 8,
            "max_workers": 2,
            "stop_on_achieved": True,
            "require_poc": False,
        },
    }
    source_fact = finding(
        category="task_goal",
        finding_kind="security_boundary",
        title="认证状态读取边界",
        poc=None,
        verifications=[{
            "id": "review-1",
            "created_at": "2026-01-01T00:05:00+00:00",
            "execution_status": "not_run",
            "verdict": "confirmed",
            "target_version": "main@abc123",
            "notes": "人工检查了引用源码行，认证边界结论成立。",
        }],
    )
    made = {
        **bundle([unit("u1", "vuln.php")]),
        "run": task_run,
        "findings": [source_fact],
        "metrics": summarise(task_run, [unit("u1", "vuln.php")], [source_fact], TRUTHS),
        "goals": [{"status": "met", "attempts": 1, "max_total_attempts": 8}],
    }

    doc = render_markdown(made)

    assert "**人工复核记录**" in doc
    assert "| 时间 | 人工结论 | 复核环境或版本 | 说明 |" in doc
    assert "main@abc123" in doc
    assert "书面人工复核确认或驳回" in doc


def test_whole_snapshot_scope_is_described_by_count_and_never_inlined():
    """A project upload can hold thousands of files, so the report must stay bounded."""
    task_run = {
        **RUN,
        "scope": [],
        "scope_mode": "snapshot",
        "task_spec": {
            "objective": "寻找未经授权的文件读取路径。",
            "success_criteria": "保存一处带原始行号的可达读取证据。",
            "max_iterations": 2,
            "max_total_attempts": 8,
            "max_workers": 2,
            "stop_on_achieved": True,
            "require_poc": False,
        },
    }
    units = [unit("u1", "src/app.php")]
    made = {
        **bundle(units),
        "run": task_run,
        "metrics": summarise(task_run, units, [], TRUTHS),
        "goals": [{"status": "unreachable", "attempts": 1, "max_total_attempts": 8}],
        # The bounded API projection is what a report export actually receives.
        "project_map": {"stats": {"files": 4213}},
    }

    doc = render_markdown(made)

    assert "上传项目整包快照，共 4213 个可读文件" in doc
    assert "4213 个已冻结源码文件" not in doc


def test_historical_explicit_scope_listing_is_capped():
    """Historical runs keep their explicit scope, but the listing is still bounded."""
    paths = [f"legacy/{index:03d}.php" for index in range(100)]
    legacy_run = {**RUN, "scope": paths}
    units = [unit("u1", "legacy/000.php")]
    made = {
        **bundle(units),
        "run": legacy_run,
        "metrics": summarise(legacy_run, units, [], TRUTHS),
    }

    doc = render_markdown(made)

    assert "`legacy/000.php`" in doc
    assert "`legacy/039.php`" in doc
    assert "`legacy/040.php`" not in doc
    assert "其余 60 个文件见 JSON 导出" in doc


PLANNER_TASK = {
    "objective": "追踪请求入口到文件读取的路径。",
    "success_criteria": "保存一处带原始行号的可达读取证据。",
    "max_iterations": 2,
    "max_total_attempts": 8,
    "max_planner_rounds": 3,
    "max_workers": 2,
    "stop_on_achieved": True,
    "require_poc": False,
}


def planner_bundle(observations, investigations=None):
    """A bundle shaped like the Planner report export, which is the live layout."""
    task_run = {**RUN, "scope": [], "scope_mode": "snapshot", "task_spec": PLANNER_TASK}
    return {
        "run": task_run,
        "goal": {"status": "inconclusive", "attempts": 1, "max_total_attempts": 8},
        "goals": [],
        "planner": {"session_id": "planner:r", "max_rounds": 3},
        "project_map": {"stats": {"files": 42}},
        "plans": [],
        "tasks": [],
        "findings": [],
        "units": [],
        "attributions": [],
        "metrics": {"task_coverage": 0},
        "observations": observations,
        "investigations": investigations or {},
    }


def coverage_payload(**overrides):
    """The event `plan_audit_frontier` emits: round on the envelope, numbers nested.

    Kept verbatim in that shape -- a fixture that flattens the numbers into the
    envelope makes the report render zeros against a payload it would never see.
    """
    return {
        "kind": "planner_coverage_prepared",
        "round": 2,
        "payload": {
            "round": 2,
            "coverage": {
                "files_total": 42,
                "files_read": 5,
                "files_with_findings": 1,
                "coverage_ratio": 0.119,
                "read_paths": ["src/auth.php"],
                "unread_hot_modules": [
                    {"module": "src", "unread": 4, "total": 9},
                    {"module": "templates", "unread": 3, "total": 3},
                ],
                "dependency_tree_total": 3,
                "dependency_tree_read": 0,
                "notice": "覆盖统计来自已持久化的 worker 读记录与冻结项目图，不是安全结论。",
                **overrides,
            },
        },
    }


def brief_payload():
    return {
        "kind": "recon_brief_prepared",
        "round": 1,
        "payload": {
            "round": 1,
            "question": "这个项目应该从哪里开始读？",
            "brief": {
                "summary": "这是一个 PHP 前端控制器项目，数据库访问集中在 src/bootstrap.php。",
                "layout": [{"path": "src", "role": "application code", "notes": "引导与路由"}],
                "entry_candidates": [
                    {"path": "public/index.php", "start_line": 1, "end_line": 3, "why": "前端控制器"},
                ],
                "data_stores": [{"path": "src/db.php", "start_line": 1, "end_line": 20, "why": "PDO"}],
                "security_boundaries": [],
                "reading_plan": [
                    {"path": f"src/module{index}.php", "start_line": 1, "end_line": 9, "why": f"第 {index} 步"}
                    for index in range(8)
                ],
                "uncertainties": ["运行时路由未确认"],
                "files_examined": ["src/bootstrap.php"],
            },
        },
    }


def test_planner_report_explains_coverage_and_reconnaissance_without_calling_it_evidence():
    """The rounds' navigation aids are exportable, but never as findings."""
    doc = render_markdown(planner_bundle([
        coverage_payload(),
        brief_payload(),
        {"kind": "recon_terminal", "round": 1, "payload": {"round": 1, "reason": "completed", "error": None}},
        {"kind": "recon_terminal", "round": 3, "payload": {"round": 3, "reason": "internal_error", "error": "RuntimeError: x"}},
    ]))

    assert "# 项目级白盒审计报告" in doc
    assert "## 6. 覆盖统计、固定调查与侦察简报" in doc
    assert "## 7. 可追溯性与后续复核" in doc
    # The boundary is stated before any number is.
    assert "它们是导航线索，不是 finding 证据，也不构成安全结论" in doc
    assert "| 2 | 5/42 | 11.9% | 1 | 0/3 | `src`（4/9）、`templates`（3/3） |" in doc
    assert "### 侦察简报（第 1 回合）" in doc
    assert "`public/index.php:1-3`（前端控制器）" in doc
    assert "`src/bootstrap.php`" in doc
    # A round that produced a brief is not also reported as a failed one.
    assert "第 1 回合侦察未产出简报" not in doc
    assert "第 3 回合侦察未产出简报：`internal_error`" in doc


def test_planner_report_bounds_the_reconnaissance_reading_plan():
    """Eight leads would be eight links in the report; only the first five travel."""
    doc = render_markdown(planner_bundle([brief_payload()]))

    assert "`src/module4.php:1-9`" in doc
    assert "`src/module5.php:1-9`" not in doc
    assert "其余 3 条见事件日志" in doc


def test_planner_report_says_when_there_is_nothing_to_report():
    doc = render_markdown(planner_bundle([]))

    assert "## 6. 覆盖统计、固定调查与侦察简报" in doc
    assert "本次运行没有覆盖统计或侦察记录。" in doc


def pinned(index, topic, *, status="active", revision=1, round_no=1, kind="recon",
           tool="investigate_project", files_read=None, superseded_by=None, reason=None,
           created_at=None):
    """One row of `Store.investigation_overview()['recent']`, payload-free as served."""
    return {
        "id": f"inv{index}", "run_id": "r" * 32, "goal_id": "g1", "plan_id": None,
        "round_no": round_no, "revision": revision, "kind": kind, "tool": tool,
        "topic": topic, "topic_key": f"k{index}", "args": {}, "payload": None,
        "payload_bytes": 512, "files_read": files_read or [], "usage": {},
        "status": status, "reason": reason, "superseded_by": superseded_by,
        "created_at": created_at or f"2026-01-01T00:0{index}:00+00:00",
    }


def overview(records, *, total=None):
    by_status: dict[str, int] = {}
    for record in records:
        by_status[record["status"]] = by_status.get(record["status"], 0) + 1
    return {"total": len(records) if total is None else total, "by_status": by_status, "recent": records}


def test_planner_report_shows_what_a_run_pinned_and_what_replaced_it():
    """A corrected investigation leaves two rows; the report prints both.

    Showing only the live row would make "investigated once, never questioned" and
    "investigated, then re-investigated and the answer changed" read the same, which is
    exactly what the write-once pin exists to distinguish.
    """
    doc = render_markdown(planner_bundle(
        [coverage_payload()],
        overview([
            pinned(1, "项目如何组织入口？", round_no=1, files_read=["public/index.php", "src/a.php"]),
            pinned(2, "项目如何组织入口？", status="superseded", revision=2, round_no=3,
                   kind="navigation", tool="list_tree", superseded_by="inv3",
                   reason="同一话题被重新调查"),
            pinned(3, "项目如何组织入口？", revision=3, round_no=4, kind="navigation",
                   tool="list_tree"),
            pinned(4, "路由在哪注册？", kind="search", tool="search_code", status="retracted",
                   reason="范围判断有误"),
        ]),
    ))

    assert "### 固定调查" in doc
    # The counts by status are stated before the table, not left to be counted by eye.
    assert "共 4 条（有效 2；已撤回 1；已被取代 1）。" in doc
    assert "一次写入，正文此后不再改写" in doc
    # Topic, kind, tool, round, revision, status, files read and pinned-at all travel.
    assert "| 项目如何组织入口？ | 侦察简报 | `investigate_project` | 1 | 1 | 有效 | `public/index.php`、`src/a.php` |" in doc
    assert "| 路由在哪注册？ | 代码检索 | `search_code` | 1 | 1 | 已撤回 | — |" in doc
    # What replaced what, named by round and revision rather than by opaque id.
    assert "已被取代：同一话题被重新调查；由第 4 回合的第 3 版「项目如何组织入口？」接替" in doc
    assert "已撤回：范围判断有误。" in doc


def test_planner_report_says_when_the_pinned_list_is_truncated():
    doc = render_markdown(planner_bundle(
        [coverage_payload()],
        overview(
            [pinned(1, "旧话题", status="superseded", revision=2, superseded_by="not-listed")],
            total=30,
        ),
    ))

    assert "本节只列最近 1 条；其余 29 条见 JSON 导出。" in doc
    # The replacement is real but outside the bounded list, and the report says so
    # instead of implying nothing replaced it.
    assert "接替它的新记录不在本节列出的范围内" in doc


def test_planner_report_keeps_the_pinned_section_when_it_is_empty_or_alone():
    """Two edges of one section: no pins at all, and pins with no coverage table."""
    with_observations = render_markdown(planner_bundle([coverage_payload()]))
    assert "### 固定调查" in with_observations
    assert "本次运行没有固定任何调查记录" in with_observations
    assert "本次运行没有覆盖统计或侦察记录。" not in with_observations

    pins_only = render_markdown(planner_bundle([], overview([pinned(1, "只有固定调查")])))
    assert "| 只有固定调查 | 侦察简报 | `investigate_project` | 1 | 1 | 有效 | — |" in pins_only
    # The section never replaces the chapter's own empty-state line for coverage.
    assert "本次运行没有覆盖统计或侦察记录。" not in pins_only
