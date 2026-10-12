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
