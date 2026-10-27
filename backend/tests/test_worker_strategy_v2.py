"""Versioned strategy contracts on unrelated source fixtures, with a mock model.

These checks exercise real evidence/settlement gates. They do not estimate an LLM's
discovery accuracy or read benchmark answers.
"""
import asyncio

import pytest

from audit import agent
from audit.config import ModelConfig
from audit.runtime import AgentPolicy
from audit.worker_strategies import builtin_worker_strategies
from tests.code_model import ModelFactory, final_answer

FILES = {
    "src/preferences.php": ["<?php", "require_user();", "$email = $_POST['email'];", "save_email($email);"],
    "src/accounts.php": ["<?php", "$password = $_POST['password'];", "$digest = md5($password);", "store_password($digest);"],
    "src/endpoint.php": ["<?php", "require 'process.php';", "run_job($_GET['value']);"],
    "src/process.php": ["<?php", "function run_job($value) {", "  shell_exec('process ' . $value);", "}"],
}


class Repository:
    def get_snapshot(self, snapshot_id):
        return {"files": [{"path": path, "line_count": len(lines)} for path, lines in FILES.items()]}

    def build_context_bundle(self, *args):
        return {"excerpts": [{"path": path, "start_line": 1, "end_line": len(lines),
            "lines": [{"number": number, "text": text} for number, text in enumerate(lines, 1)]}
            for path, lines in FILES.items()]}


def test_old_strategy_texts_and_new_parentage_are_immutable():
    strategies = {item["id"]: item for item in builtin_worker_strategies()}
    assert strategies["worker-w0-v1"]["text"] == "识别当前任务中由源码支持的可操作漏洞，说明影响，并准确指出根因或危险操作的位置。"
    assert strategies["worker-w1-v1"]["text"] == strategies["worker-w0-v1"]["text"] + "逐项核对攻击者输入来源、传播路径、关键操作及已有防护；说明防护是否覆盖当前输入路径，不能只凭函数名称判断。"
    for level in (1, 2):
        value = strategies[f"worker-w{level}-v2"]
        assert value["parent_id"] == f"worker-w{level}-v1"
        assert value["contract_version"] == "worker-strategy-v1"
        assert all(secret not in value["text"].casefold() for secret in
            ("lab30", "ground_truth", "scoring_anchor", "account/settings.php", "30项", "真值14"))


@pytest.mark.parametrize("strategy_id", ["worker-w1-v2", "worker-w2-v2"])
@pytest.mark.parametrize("cause,path,line,refs", [
    ("csrf", "src/preferences.php", 4, "src/preferences.php:1-4"),
    ("weak_crypto", "src/accounts.php", 3, "src/accounts.php:2-4"),
    ("command_injection", "src/process.php", 3, "src/endpoint.php:1-3; src/process.php:1-4"),
])
def test_new_strategies_preserve_root_location_evidence_and_unknown_cvss(monkeypatch, strategy_id, cause, path, line, refs):
    strategy = next(item for item in builtin_worker_strategies() if item["id"] == strategy_id)
    payload = {"outcome": "achieved", "summary": "已读源码形成独立的风险结论。", "reasoning": "按根因定位，缺少部署事实时保留未知评分。",
        "findings": [{"kind": "vulnerability", "title": "源码边界缺陷", "summary": "输入进入敏感操作，未见相应边界处理。",
            "vulnerability_type": cause, "primary_location": {"path": path, "line": line},
            "evidence": refs, "dangerous_operation": FILES[path][line - 1], "cvss_input": {}}]}
    model = ModelFactory([final_answer(payload)])
    monkeypatch.setattr(agent, "build_code_model", model)
    result = asyncio.run(agent.pursue_planner_task(
        repository=Repository(), snapshot_id="fixture", snapshot_name="unrelated-source.zip",
        planner_task={"id": "task", "task_key": "fixture", "title": "核对源码边界"},
        run_task={"objective": "核对源码与适用条件", "require_poc": False}, attempt=1, allowed_paths=None,
        config=ModelConfig(model="offline", base_url="https://example.invalid", api_key="fixture"),
        budgets={"responses": 2, "tools": 0, "seconds": 3}, policy=AgentPolicy(request_seconds=1), worker_strategy=strategy,
    ))
    assert result["outcome"] == "achieved", result
    finding = result["result"]["findings"][0]
    assert finding["primary_location"] == {"path": path, "line": line}
    assert finding["vulnerability_type"] == cause
    assert not finding.get("cvss_input")
    assert strategy["text"] in model.prompts[0]
    assert "不确定时" in model.prompts[0] and "primary_location" in model.prompts[0]
