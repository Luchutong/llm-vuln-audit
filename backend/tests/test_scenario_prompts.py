"""The scenario-limited prompt versions (S-sqli / S-xss / S-cmd).

These pin the contract the deliverable claims: the three scenario records exist next
to P0/P1/P2, keep the four-section layout, and never break the shared output schema --
a scenario run still fills all three category fields, so downstream parsing, metrics
and reports need no scenario branch.
"""
from __future__ import annotations

import pytest

from audit.prompts import (
    BUILTIN_PROMPTS,
    SCENARIO_PROMPTS,
    builtin_prompt_records,
    scenario_prompt_records,
)

SECTIONS = ("# 一、审计角色", "# 二、核心任务", "# 三、漏洞判定标准", "# 四、输出格式")


def test_three_scenario_versions_exist_with_stable_ids():
    assert set(SCENARIO_PROMPTS) == {"sqli", "xss_r", "command_injection"}
    assert [SCENARIO_PROMPTS[key]["id"] for key in ("sqli", "xss_r", "command_injection")] == [
        "S-sqli", "S-xss", "S-cmd",
    ]


@pytest.mark.parametrize("key", ["sqli", "xss_r", "command_injection"])
def test_four_section_layout_is_intact(key):
    text = SCENARIO_PROMPTS[key]["text"]
    cursor = 0
    for section in SECTIONS:
        found = text.find(section, cursor)
        assert found != -1, f"{key}: 缺少 {section}"
        cursor = found
    # 四段必须按顺序出现，中间不得重复。
    for section in SECTIONS:
        assert text.count(section) == 1, f"{key}: {section} 出现次数不为 1"


@pytest.mark.parametrize("key", ["sqli", "xss_r", "command_injection"])
def test_output_contract_stays_three_category(key):
    """场景版仍要求三字段全填，非目标类别一律 no_candidate。"""
    text = SCENARIO_PROMPTS[key]["text"]
    for field in ("`sqli`", "`xss_r`", "`command_injection`"):
        assert field in text, f"{key}: 输出契约缺少 {field}"
    assert "no_candidate" in text
    assert "非目标场景" in text or "非本次目标场景" in text


def test_scenario_criteria_are_scenario_specific():
    assert "prepare/execute" in SCENARIO_PROMPTS["sqli"]["text"]
    assert "htmlspecialchars" in SCENARIO_PROMPTS["xss_r"]["text"]
    assert "escapeshellarg" in SCENARIO_PROMPTS["command_injection"]["text"]
    # 每个场景都保住证据链与行号这条底线。
    for record in SCENARIO_PROMPTS.values():
        assert "输入来源 → 传播路径" in record["text"]
        assert "行号" in record["text"]


def test_scenario_records_are_not_builtin_and_share_record_shape():
    builtin_ids = {row["id"] for row in BUILTIN_PROMPTS}
    assert not builtin_ids & {"S-sqli", "S-xss", "S-cmd"}
    for record in builtin_prompt_records():
        assert record["id"] not in SCENARIO_PROMPTS
    for record in scenario_prompt_records():
        assert set(record) - {"scenario"} >= {"id", "label", "phase", "reason", "text", "created_at"}
        assert record["phase"] == "custom"
