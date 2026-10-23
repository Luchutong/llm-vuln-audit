"""Goal workers navigate the uploaded snapshot instead of probing host paths."""
from __future__ import annotations

import asyncio
import io
import zipfile

from audit import agent
from audit.config import ModelConfig
from audit.runtime import AgentPolicy
from audit.source import SourceRepository
from tests.code_model import ModelFactory, code

CONFIG = ModelConfig(model="test", base_url="https://example.invalid", api_key="test-key")
FILES = {
    "src/upload.php": "<?php\n$name = basename($_FILES['file']['name']);\nmove_uploaded_file($tmp, $base . $name);\n",
    "config/.htaccess": "<FilesMatch \\.php$>\nRequire all denied\n</FilesMatch>\n",
    "private/hidden.php": "<?php echo 'out of scope';\n",
}


def run_worker(tmp_path, monkeypatch, action, *, allowed=None, steps=5):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for path, text in FILES.items():
            archive.writestr(path, text)
        archive.writestr("assets/binary.png", b"\x89PNG\x00\xff\x00")
    repo = SourceRepository(tmp_path)
    snapshot = repo.import_zip(buf.getvalue(), "project.zip")
    factory = ModelFactory({"task_execute": [code(action)]})
    monkeypatch.setattr(agent, "build_code_model", factory)
    events = []
    result = asyncio.run(agent.pursue_task_work(
        repository=repo, snapshot_id=snapshot["id"], snapshot_name="project.zip",
        unit={"file_path": "src/upload.php", "symbol": "upload", "kind": "planner_context", "start_line": 1, "end_line": 3,
              "slice_index": 1, "slice_count": 1,
              "cleaned_lines": [{"number": 1, "text": "<?php"}]},
        task={"objective": "检查上传路径约束与部署配置。", "success_criteria": "仅使用已读取的源码引用报告漏洞。", "require_poc": False},
        attempt=1, allowed_paths=allowed, config=CONFIG,
        initial_excerpts=[{"path": "src/upload.php", "lines": [{"number": 1, "text": "<?php"}]}],
        budgets={"responses": steps, "tools": 8, "seconds": 10},
        policy=AgentPolicy(request_seconds=1), on_event=events.append,
    ))
    return result, events, factory


def test_worker_can_parse_listings_and_read_the_actual_configuration_in_one_response(tmp_path, monkeypatch):
    result, events, factory = run_worker(tmp_path, monkeypatch, """
import json
files = json.loads(find_files(pattern='.htaccess'))
listing = json.loads(list_tree(path='config'))
path = files['matches'][0]['path']
assert path == listing['files_here'][0]['path']
print(read_source(path=path, start=1, end=3))
final_answer({'outcome':'no_evidence', 'summary':'已核对上传文件名处理和已上传的部署配置。',
 'reasoning':'配置分支有访问限制，但不能据此判断所有部署环境。',
 'observations':[{'title':'已上传的脚本访问限制', 'kind':'security_boundary',
 'summary':'配置中对 PHP 文件匹配后拒绝访问，结论仅覆盖当前已上传配置。', 'evidence':'config/.htaccess:1-3'}]})
""")
    assert result["outcome"] == "no_evidence", result
    assert result["usage"]["requests"] == 1
    assert result["usage"]["tool_calls"] == 3
    assert len(factory.prompts) == 1
    assert not [event for event in events if event["kind"] == "agent_code" and event.get("error")]
    assert result["result"]["observations"][0]["evidence"] == "config/.htaccess:1-3"
    refs = [item for item in result["seen"] if item["path"] == "config/.htaccess"]
    assert refs


def test_worker_navigation_respects_frozen_scope_without_adding_source_evidence(tmp_path, monkeypatch):
    result, events, _ = run_worker(tmp_path, monkeypatch, """
import json
files = json.loads(find_files(pattern='**/*'))
assert [item['path'] for item in files['matches']] == ['src/upload.php']
listing = json.loads(list_tree())
assert [item['path'] for item in listing['child_directories']] == ['src']
assert json.loads(find_files(pattern='.htaccess'))['matches'] == []
final_answer({'outcome':'blocked', 'summary':'当前冻结范围没有部署配置，无法核对访问策略。',
 'reasoning':'导航仅列出上传处理文件，没有读取任何额外源码。',
 'missing_context':['部署配置未包含在当前快照范围内。']})
""", allowed={"src/upload.php"})
    assert result["outcome"] == "blocked", result
    assert {item["path"] for item in result["seen"]} == {"src/upload.php"}
    assert result["usage"]["tool_calls"] == 3
    assert all(event["new_lines"] == 0 for event in events if event["kind"] == "tool_result")
    assert result["result"]["findings"] == []


def test_worker_navigation_does_not_let_listed_paths_be_cited_as_read_source(tmp_path, monkeypatch):
    result, events, _ = run_worker(tmp_path, monkeypatch, """
import json
files = json.loads(find_files(pattern='.htaccess'))
final_answer({'outcome':'no_evidence', 'summary':'仅列出配置路径，未实际读取内容。',
 'reasoning':'此引用没有对应的源码读取，不应被宿主接受。',
 'observations':[{'title':'不能凭目录声明配置安全', 'kind':'security_boundary',
 'summary':'目录里列出了配置文件，但没有显示任何原始源码。', 'evidence':'config/.htaccess:1-3'}]})
""", steps=4)
    assert result["outcome"] != "achieved"
    assert not [event for event in events if event["kind"] == "task_assessment"]
    assert any("证据必须来自已显示源码" in event.get("error", "") for event in events if event["kind"] == "agent_code")


def test_missing_path_feedback_names_the_snapshot_navigation_tools(tmp_path, monkeypatch):
    result, events, _ = run_worker(tmp_path, monkeypatch, """
print(read_source(path='hackable/uploads/.htaccess', start=1, end=10))
final_answer({'outcome':'blocked', 'summary':'上传包没有部署目录的配置文件。',
 'reasoning':'读取返回缺失上下文，不能假设部署配置已存在。', 'missing_context':['上传目录的部署访问规则。']})
""")
    assert result["outcome"] == "blocked"
    error = next(event for event in events if event["kind"] == "tool_result" and event["status"] == "context_missing")
    assert "find_files 或 list_tree" in error["preview"]
    assert result["result"]["missing_context"]
