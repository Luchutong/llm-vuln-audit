"""In-memory codeagent API for browser checks; no audit or provider is contacted."""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

STAMP = "2026-10-20T08:30:00+00:00"
PROJECT_ID = "smoke-project"
OTHER_PROJECT_ID = "smoke-other-project"
EMPTY_PROJECT_ID = "smoke-empty-project"
SNAPSHOT_ID = "smoke-snapshot"
NEWER_SNAPSHOT_ID = "smoke-snapshot-repacked"
OTHER_SNAPSHOT_ID = "smoke-other-snapshot"
LEDGER_ID = "ledger-upload-boundary"
STALE_LEDGER_ID = "ledger-stale-conclusion"
COMPLETED_ID = "smoke-completed"
CREATED_ID = "smoke-created"
ACTIVITY_ID = "smoke-live-activity"
SOURCE_PATH = "src/upload.php"
OBJECTIVE = "检查上传入口到文件写入的安全边界并提供源码证据。"
CRITERIA = "引用输入来源、传播路径和敏感操作的原始行号；无法确认时说明缺失上下文。"
LONG_VALUE = "LONG_PAYLOAD_START\n" + "工具返回的长文本与无空格路径/" * 700 + "\nLONG_PAYLOAD_END"
LONG_LOG = "PRINT_LOG_START\n" + "已读取的源码观察与批处理日志。\n" * 600 + "PRINT_LOG_END\n[日志已截断]"
BUDGET = {"responses": 24, "tools": 96, "seconds": 1800}
RUN_LIMITS = {"responses": 256, "tools": 2048, "seconds": 1800}
FULL_RUN_LIMITS = {"responses": 512, "tools": 4096, "seconds": 3600}
USAGE = {"requests": 4, "tool_calls": 2, "input_tokens": 2300, "output_tokens": 700}
TASK = {"objective": OBJECTIVE, "success_criteria": CRITERIA, "max_iterations": 3,
        "max_total_attempts": 64, "max_planner_rounds": 24, "max_workers": 2,
        "stop_on_achieved": True, "require_poc": False}
ACTIVE = {"pending", "running", "paused"}


def snapshot() -> dict[str, Any]:
    files = []
    for index, (path, language, binary, dependency) in enumerate([
        (SOURCE_PATH, "php", False, False), ("src/auth.php", "php", False, False),
        ("vendor/dependency.php", "php", False, True),
        ("src/client.ts", "typescript", False, False), ("config/settings.yaml", "yaml", False, False),
        ("assets/logo.png", "binary", True, False),
    ]):
        php = language == "php"
        files.append({"path": path, "sha256": str(index) * 64, "size": 2400,
                      "line_count": 0 if binary else 80, "kind": "binary" if binary else "text",
                      "language": language, "is_php": php, "dependency_tree": dependency,
                      "excluded": dependency or not php, "exclude_reason": "historical metadata" if dependency or not php else None,
                      "parse_errors": []})
    return {"id": SNAPSHOT_ID, "name": "审计样例源码.zip", "created_at": STAMP,
            "project_id": PROJECT_ID, "content_key": "c" * 64, "target_profile": "unknown",
            "archive_sha256": "a" * 64, "source": "uploaded_zip", "immutable": True, "schema_version": 2,
            "warnings": ["1 files were skipped at import; see skipped_files for details"], "units": [], "files": files,
            "stats": {"files": 6, "text_files": 5, "binary_files": 1, "php_files": 3,
                      "dependency_tree_files": 1, "languages": {"php": 3, "typescript": 1, "yaml": 1},
                      "skipped_count": 1, "excluded_count": 4},
            "skipped_files": [{"path": "build/oversized.js", "reason": "file_too_large"}],
            "excluded_files": [item["path"] for item in files if item["excluded"]],
            "import_limits": {"archive_bytes": 64 * 1024 * 1024, "extracted_bytes": 256 * 1024 * 1024,
                              "file_bytes": 8 * 1024 * 1024, "entries": 40000, "compression_ratio": 1000}}


def run(run_id: str = COMPLETED_ID, status: str = "completed") -> dict[str, Any]:
    return {"id": run_id, "snapshot_id": SNAPSHOT_ID, "snapshot_name": snapshot()["name"],
            "project_id": PROJECT_ID, "project_name": "审计样例源码", "project_mode": "project",
            "scope": [], "scope_mode": "snapshot", "model": "ui-fixture-model",
            "model_profile": {"profile_id": "profile-environment", "model": "ui-fixture-model", "base_url": "http://fixture.invalid/v1"},
            "budgets": copy.deepcopy(BUDGET), "task_spec": copy.deepcopy(TASK), "status": status,
            "created_at": STAMP, "started_at": STAMP, "finished_at": None if status in ACTIVE else STAMP,
            "usage": copy.deepcopy(USAGE), "total_tasks": 1, "completed_tasks": int(status == "completed")}


def finding(run_id: str) -> dict[str, Any]:
    return {"id": f"finding-{run_id}", "run_id": run_id, "task_id": "task-upload", "task_key": "upload-boundary",
            "fingerprint": "fixture-fingerprint", "category": "task_goal", "finding_kind": "vulnerability",
            "title": "上传路径写入边界需要人工复核", "severity": "medium",
            "summary": "输入路径到文件写入的可达关系已定位。" + "需要结合部署配置核对前置条件。" * 45,
            "file_path": SOURCE_PATH, "symbol": "upload", "line": 12, "unit_start_line": 1, "unit_end_line": 40,
            "validation_state": "candidate", "validation_errors": [], "evidence": [
                {"snapshot_id": SNAPSHOT_ID, "path": SOURCE_PATH, "start_line": 10, "end_line": 12},
                {"snapshot_id": SNAPSHOT_ID, "path": "src/auth.php", "start_line": 8, "end_line": 9}],
            "input_source": "请求参数 name", "propagation": "输入经字符串拼接后传入文件操作。",
            "dangerous_operation": "file_put_contents", "protection": "认证前置条件需要复核", "preconditions": ["有上传权限"],
            "missing_context": ["运行时上传目录配置"], "poc": None, "remediation": "校验文件名并将写入范围约束在固定目录。",
            "verdict": "uncertain", "verifications": [], "disposition": "open", "revision": 2,
            "disposition_reason": None, "disposition_by": None, "disposition_at": None, "derived_from_finding_id": None,
            "superseded_summary": [{"revision": 1, "title": "先前的上传路径观察", "summary": "此前尚未核对认证依赖。",
                                    "evidence": [], "disposition": "open", "created_at": STAMP}]}


def source_observations(run_id: str) -> list[dict[str, Any]]:
    historical = finding(run_id)
    historical.update(id=f"observation-{run_id}", finding_kind="data_flow", severity="informational",
                      title="上传路径已规范化，没有目录穿越证据", summary="写入前使用 basename 规范化文件名，已检查路径未构成目录穿越漏洞。",
                      verdict="confirmed", poc=None, input_source="请求参数 name", propagation="参数传入 basename 后写入固定目录。",
                      protection="basename 路径规范化", remediation="", missing_context=[],
                      superseded_summary=[{"revision": 1, "title": "早期路径观察", "summary": "最初尚未核对路径规范化。", "evidence": []}],
                      verifications=[{"id": "observation-review", "created_at": STAMP, "verdict": "confirmed", "execution_status": "not_run",
                                      "notes": "历史人工排查记录：已核对 basename 防护，原始记录保留。", "target_version": "fixture-commit",
                                      "command": "", "modified_script": "", "normal_observation": "", "attack_observation": "",
                                      "files": [{"name": "历史代码评审.txt", "url": "/api/evidence/historical-review.txt"}]}])
    # A projected worker-attempt observation has a source location and attempt identity.
    current = {"id": f"observation:{run_id}:1:0", "run_id": run_id, "task_id": "task-upload", "task_key": "upload-boundary", "attempt": 1,
               "title": "已确认上传入口的认证边界", "summary": "上传处理器前执行会话认证，未发现认证绕过证据。", "category": "audit_observation",
               "file_path": "src/auth.php", "line": 8, "unit_start_line": 8, "unit_end_line": 9,
               "finding_kind": "security_boundary", "severity": "informational", "validation_state": "observation", "validation_errors": [],
               "evidence": [{"snapshot_id": SNAPSHOT_ID, "path": "src/auth.php", "start_line": 8, "end_line": 9}],
               "verdict": None, "verifications": []}
    return [historical, current]


def project_map(item: dict[str, Any]) -> dict[str, Any]:
    return {"snapshot_id": item["snapshot_id"], "run_id": item["id"], "scope_files": 5,
            "entrypoints": [{"path": SOURCE_PATH, "confidence": "high", "reason": "请求入口"}],
            "directories": ["src", "config", "vendor"], "binary_files": [{"path": "assets/logo.png", "size": 2400, "readable": False}],
            "architecture": {"modules": [{"directory": "src", "files": 3, "role": "application"}]},
            "stats": {"files": 5, "text_files": 5, "binary_files": 1, "symbols": 3, "includes": 1, "calls": 2, "entrypoints": 1},
            "limitations": ["静态图不能替代运行时调用图。"], "omitted": ["files", "symbols", "includes", "calls"],
            "full_map_path": f"/api/runs/{item['id']}/project-map"}


def detail(item: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    done = item["status"] not in ACTIVE
    withdrawn = observed.get("disposition", "open") in {"superseded", "retracted", "duplicate"}
    candidate = int(observed["validation_state"] == "candidate" and not withdrawn)
    task_state = "completed" if done else "ready" if item["status"] == "paused" else "running"
    coverage = {"files_total": 5, "files_read": 2, "files_with_findings": 2, "coverage_ratio": 0.4,
                "read_paths": [SOURCE_PATH, "src/auth.php"], "dependency_tree_total": 1, "dependency_tree_read": 0,
                "unread_hot_modules": [], "notice": "导航统计，不是安全结论或证据。"}
    return {"run": copy.deepcopy(item),
            "goal": {"id": "goal-smoke", "run_id": item["id"], **copy.deepcopy(TASK),
                     "status": "met" if item["status"] == "completed" else "inconclusive" if done else "open", "attempts": 1,
                     "terminal_reason": "已定位源码证据；请人工确认运行环境。" if done else None, "created_at": STAMP, "updated_at": STAMP},
            "planner": {"run_id": item["id"], "goal_id": "goal-smoke", "session_id": "session-smoke",
                        "status": "completed" if done else "dispatching", "current_round": 1, "max_rounds": 24,
                        "current_revision": 1, "created_at": STAMP, "updated_at": STAMP},
            "plans": [{"id": "plan-smoke", "run_id": item["id"], "goal_id": "goal-smoke", "session_id": "session-smoke",
                       "round_no": 1, "revision": 1, "status": "completed", "basis_summary": "从上传入口追踪路径拼接与写入调用。",
                       "next_action": "检查认证依赖。", "task_snapshot": [{"task_key": "upload-boundary", "title": "上传路径追踪"}], "created_at": STAMP}],
            "tasks": [{"id": "task-upload", "task_key": "upload-boundary", "title": "上传路径追踪", "objective": OBJECTIVE,
                       "acceptance_criteria": CRITERIA, "context_spec": {"source_refs": [{"path": SOURCE_PATH, "start_line": 1, "end_line": 40}],
                       "scope_paths": ["src"], "target_symbols": ["upload"]}, "session_id": "session-smoke", "priority": 50,
                       "state": task_state, "max_attempts": 3, "attempts": 1, "dependencies": [], "claimed_by": "worker-1",
                       "result": {"outcome": "achieved", "summary": "已定位写入调用。", "reasoning": "源码引用可核对。"},
                       "attempt_history": [], "created_at": STAMP, "updated_at": STAMP}],
            "project_map": project_map(item),
            "observations": [{"kind": "planner_coverage_prepared", "payload": {"round": 1, "coverage": coverage}}],
            "investigations": {"total": 1, "by_status": {"active": 1, "superseded": 0, "retracted": 0},
                               "notice": "固定调查正文按需读取，当前响应只包含元数据。", "recent": [
                                   {"id": "investigation-smoke", "round_no": 1, "revision": 1, "kind": "recon", "tool": "investigate_project",
                                    "topic": "定位上传入口", "topic_key": "upload-entry", "args": {"question": "定位上传入口"}, "payload": None,
                                    "payload_bytes": 3000, "files_read": [], "usage": {}, "status": "active", "created_at": STAMP}]},
            "findings": [copy.deepcopy(observed)], "source_observations": source_observations(item["id"]), "units": [], "goals": [], "work_items": [], "attributions": [],
            "metrics": {"candidates": candidate, "candidate_findings": candidate, "discarded_candidates": 0, "withdrawn_findings": int(withdrawn),
                        "source_observations": 2,
                        "confirmed": int(observed["verdict"] == "confirmed"), "rejected": 0, "uncertain": int(observed["verdict"] != "confirmed"),
                        "awaiting_verification": 0, "audit_coverage": float(done), "task_coverage": float(done), "verification_coverage": 0,
                        "total_units": 0, "completed_units": 0, "incomplete_units": 0, "pending_units": 0, "total_tasks": 1,
                        "completed_tasks": int(done), "terminal_tasks": int(done), "active_tasks": int(not done),
                        "truth_status": "planner_goal_not_comparable", "evaluation": None}}


def event(run_id: str, number: int, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(payload)
    role = payload.setdefault("role", "planner" if kind.startswith("planner_") else "host" if kind.startswith("run_") else "worker")
    if role in {"planner", "recon"}:
        payload.setdefault("plan_id", "plan-smoke")
        payload.setdefault("session_id", "session-smoke")
    if role == "worker":
        for key, value in {"task_id": "task-upload", "task_key": "upload-boundary", "worker_id": "worker-1", "attempt": 1}.items():
            payload.setdefault(key, value)
    return {"id": number, "run_id": run_id, "unit_id": payload.get("task_id") if role == "worker" else None,
            "kind": kind, "payload": payload, "created_at": STAMP}


def activity_events(run_id: str = ACTIVITY_ID) -> list[dict[str, Any]]:
    """Ordered activity replay; the smoke runner releases each frame explicitly."""
    worker_a = {"role": "worker", "task_id": "task-upload", "task_key": "upload-boundary",
                "worker_id": "worker-a", "attempt": 1, "agent_invocation_id": "fixture-invocation-a", "request_index": 1}
    worker_b = {**worker_a, "task_id": "task-auth", "task_key": "auth-boundary",
                "worker_id": "worker-b", "agent_invocation_id": "fixture-invocation-b"}
    retry = {**worker_a, "attempt": 2, "agent_invocation_id": "fixture-invocation-retry"}
    path = "src/上传处理与认证边界/" + "无空格路径" * 16 + ".php"
    items = [
        event(run_id, 1, "run_started", {"role": "host"}),
        event(run_id, 2, "planner_round_started", {"role": "planner", "round": 1}),
        event(run_id, 3, "audit_progress", {"role": "planner", "agent_invocation_id": "fixture-planner",
              "request_index": 1, "source": "agent", "message": "先检查上传入口的路径处理，再核对认证边界和文件写入。"}),
        event(run_id, 4, "tool_call", {**worker_a, "tool": "read_source", "call_id": "reused-call", "span_id": "explore:reused-call",
              "phase": "explore", "args": {"path": SOURCE_PATH, "start": 10, "end": 12, "context": LONG_VALUE}}),
        event(run_id, 5, "tool_call", {**worker_b, "tool": "read_source", "call_id": "reused-call", "span_id": "explore:reused-call",
              "phase": "explore", "args": {"path": path, "start": 8, "end": 9}}),
        event(run_id, 6, "tool_result", {**worker_b, "tool": "read_source", "call_id": "reused-call", "span_id": "explore:reused-call",
              "phase": "explore", "status": "ok", "preview": "WORKER_B_RETURN：认证入口拒绝未登录请求。", "duration_ms": 12}),
        event(run_id, 7, "tool_result", {**worker_a, "tool": "read_source", "call_id": "reused-call", "span_id": "explore:reused-call",
              "phase": "explore", "status": "ok", "preview": "WORKER_A_RETURN：路径值进入文件写入调用。", "new_lines": 3, "duration_ms": 21}),
        event(run_id, 8, "audit_progress", {**worker_a, "source": "agent", "message": "已定位文件写入点，接下来排查是否存在可利用的路径绕过。"}),
        event(run_id, 9, "tool_call", {**worker_a, "tool": "search_code", "call_id": "missing-search",
              "args": {"query": "canonicalize_path"}}),
        event(run_id, 10, "tool_result", {**worker_a, "tool": "search_code", "call_id": "missing-search", "status": "error",
              "error": "模拟检索暂时失败，请缩小搜索范围后重试。", "preview": "Error: 模拟检索暂时失败", "duration_ms": 5}),
        event(run_id, 11, "planner_task_requeued", {**worker_a, "state": "ready", "summary": "补读安全边界后继续核对。"}),
        event(run_id, 12, "audit_progress", {**retry, "source": "agent", "message": "第二次尝试只补读路径规范化相关源码，不重复已确认的认证检查。"}),
        event(run_id, 13, "tool_call", {**retry, "tool": "read_source", "call_id": "reused-call", "span_id": "explore:reused-call",
              "phase": "explore", "args": {"path": SOURCE_PATH, "start": 24, "end": 28}}),
        event(run_id, 14, "tool_result", {**retry, "tool": "read_source", "call_id": "reused-call", "span_id": "explore:reused-call",
              "phase": "explore", "status": "ok", "preview": "RETRY_RETURN：补读了目录约束和文件名规范化代码。", "duration_ms": 9}),
    ]
    for index in range(65):
        number = 15 + index * 3
        items.extend([
            event(run_id, number, "audit_progress", {**retry, "request_index": index + 2,
                  "message": f"第 {index + 1} 个排查方向已核对：继续比较输入路径、权限边界和部署条件。"}),
            event(run_id, number + 1, "tool_call", {**retry, "request_index": index + 2, "tool": "search_code",
                  "call_id": f"history-{index}", "args": {"query": f"upload_boundary_{index}"}}),
            event(run_id, number + 2, "tool_result", {**retry, "request_index": index + 2, "tool": "search_code",
                  "call_id": f"history-{index}", "status": "ok", "preview": f"方向 {index + 1} 已读取相关源码。", "duration_ms": 3}),
        ])
    for index in range(6):
        number = items[-1]["id"] + 1
        items.extend([
            event(run_id, number, "tool_call", {**retry, "request_index": 68, "tool": "search_code",
                  "call_id": f"batch-history-{index}", "args": {"query": f"deployment_boundary_{index}"}}),
            event(run_id, number + 1, "tool_result", {**retry, "request_index": 68, "tool": "search_code",
                  "call_id": f"batch-history-{index}", "status": "ok", "preview": "已核对部署条件引用。", "duration_ms": 2}),
        ])
    items.append(event(run_id, items[-1]["id"] + 1, "audit_progress", {
        **retry, "request_index": 69, "message": "源码路径与认证边界已核对，正在汇总部署条件和仍需人工复核的风险。",
    }))
    return items


def events(run_id: str, large: bool = False) -> list[dict[str, Any]]:
    items = [
        event(run_id, 1, "planner_round_started", {"round": 1, "role": "planner", "basis_summary": "追踪上传入口"}),
        event(run_id, 2, "tool_call", {"tool": "read_source", "args": {"path": SOURCE_PATH, "start": 1, "end": 40, "context": LONG_VALUE}, "call_id": "tool-smoke", "span_id": "explore:tool-smoke", "phase": "explore"}),
        event(run_id, 3, "tool_result", {"tool": "read_source", "status": "ok", "preview": LONG_VALUE[:1200], "chars": len(LONG_VALUE), "new_lines": 40, "duration_ms": 18, "call_id": "tool-smoke", "span_id": "explore:tool-smoke", "phase": "explore"}),
        event(run_id, 4, "task_assessment", {"summary": "已定位写入调用", "rationale": "请求输入可沿拼接路径到达写入调用；部署目录配置待复核。", "outcome": "achieved"}),
        event(run_id, 5, "agent_code", {"phase": "explore", "step": 1, "code": "for path in paths:\n    print(read_source(path, 1, 40))\n" * 20,
                                     "code_bytes": 12000, "truncated": True, "logs": LONG_LOG, "is_final": False,
                                     "error": "OutputRejected: 首次结论缺少行号，下一步已更正。", "usage": USAGE}),
        event(run_id, 6, "recon_started", {"role": "recon", "round": 1, "question": "定位上传入口", "phase": "recon_explore"}),
        event(run_id, 7, "tool_call", {"role": "recon", "tool": "find_files", "args": {"pattern": "**/*.ts"}, "call_id": "recon-tool-0001", "span_id": "recon_explore:recon-tool-0001", "phase": "recon_explore"}),
        event(run_id, 8, "tool_result", {"role": "recon", "tool": "find_files", "status": "ok", "preview": "src/client.ts", "call_id": "recon-tool-0001", "span_id": "recon_explore:recon-tool-0001", "phase": "recon_explore", "duration_ms": 9}),
        event(run_id, 9, "recon_brief_prepared", {"role": "recon", "round": 1, "question": "定位上传入口", "brief": {"summary": "入口涉及 PHP 处理器与 TypeScript 客户端。", "files_examined": [SOURCE_PATH, "src/client.ts"]}}),
        event(run_id, 10, "recon_terminal", {"role": "recon", "round": 1, "reason": "completed"}),
        event(run_id, 11, "planner_coverage_prepared", {"round": 1, "coverage": {"files_total": 5, "files_read": 2, "coverage_ratio": 0.4}}),
    ]
    if large:
        items.extend(event(run_id, number, "model_response", {"status": "recorded", "response": number}) for number in range(12, 2001))
        items.append(event(run_id, 2001, "run_completed", {"goal_status": "met"}))
    return items


def profiles() -> list[dict[str, Any]]:
    return [{"id": profile_id, "label": label, "model": model, "base_url": "http://fixture.invalid/v1",
             "credential_source": source, "api_key_configured": True, "ordinal": ordinal,
             "created_at": STAMP, "updated_at": STAMP, "selected": ordinal == 0}
            for ordinal, (profile_id, label, model, source) in enumerate([
                ("profile-environment", "本地环境模型", "ui-fixture-model", "environment"),
                ("profile-secondary", "备用模型档案", "ui-secondary-model", "stored")])]


def ledger_finding(ledger_id: str = LEDGER_ID) -> dict[str, Any]:
    """Canonical content differs from its first run: detail must use this revision."""
    value = finding(COMPLETED_ID)
    value.update(id=ledger_id, project_id=PROJECT_ID, project_name="审计样例源码", revision=2,
                 title="上传路径可绕过目录边界", summary="当前台账结论：路径规范化顺序可被绕过，写入范围超出固定目录。",
                 origin_run_id=COMPLETED_ID, origin_finding_id=f"finding-{COMPLETED_ID}",
                 last_run_id=COMPLETED_ID, last_finding_id=f"finding-{COMPLETED_ID}",
                 discovered_at=STAMP, updated_at=STAMP, verification_status="verified", verification_verdict="confirmed",
                 poc={"filename": "upload-proof.py", "language": "python", "script": "print('fixture proof')",
                      "instructions": "仅在隔离测试环境执行。", "normal_input": "safe.txt", "attack_input": "../proof.txt",
                      "expected_result": "写入测试目录外。"})
    return value


def verification_record(ledger_id: str = LEDGER_ID) -> dict[str, Any]:
    """A valid proof from an early run remains visible after rediscovery."""
    return {"id": "verification-early-run", "source": "poc_agent", "status": "verified", "verdict": "confirmed",
            "execution_status": "success", "created_at": STAMP, "finding_id": f"finding-{COMPLETED_ID}",
            "run_id": COMPLETED_ID, "project_finding_id": ledger_id, "finding_revision": 2,
            "notes": "早期审计已在隔离靶场复现，后续任务只重新发现相同结论。", "modified_script": "",
            "modification_notes": "", "target_version": "fixture-commit", "command": "python upload-proof.py",
            "expected_result": "写入测试目录外。", "normal_observation": "普通文件写入限定目录。",
            "attack_observation": "攻击输入写入目录外。", "browser_execution": False, "files": [], "jobs": []}


@dataclass
class MockAPI:
    """Strict router: unhandled API calls fail locally and never reach a real service."""
    snapshot_records: dict[str, dict[str, Any]] = field(default_factory=lambda: {SNAPSHOT_ID: snapshot()})
    project_names: dict[str, str] = field(default_factory=lambda: {PROJECT_ID: "审计样例源码"})
    ledger_records: dict[str, dict[str, Any]] = field(default_factory=lambda: {LEDGER_ID: ledger_finding()})
    ledger_verifications: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: {LEDGER_ID: [verification_record()]})
    ledger_queries: list[dict[str, str]] = field(default_factory=list)
    read_failures: dict[str, int] = field(default_factory=dict)
    read_counts: dict[str, int] = field(default_factory=dict)
    held_paths: set[str] = field(default_factory=set)
    pending_reads: list[Any] = field(default_factory=list)
    upload_result: dict[str, Any] | None = None
    upload_project_reused: bool = True
    snapshot_read_failures: dict[str, int] = field(default_factory=dict)
    runs: dict[str, dict[str, Any]] = field(default_factory=lambda: {COMPLETED_ID: run()})
    findings: dict[str, dict[str, Any]] = field(default_factory=lambda: {COMPLETED_ID: finding(COMPLETED_ID)})
    detail_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    model_profiles: list[dict[str, Any]] = field(default_factory=profiles)
    selected_profile_id: str = "profile-environment"
    # Only hashes are retained to test omission/clearing. Real encryption is covered by backend tests.
    key_fingerprints: dict[str, str] = field(default_factory=lambda: {"profile-secondary": "existing-encrypted-key-fixture"})
    profile_requests: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    config_responses: list[dict[str, Any]] = field(default_factory=list)
    extra_events: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    event_overrides: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    upload_count: int = 0
    create_count: int = 0
    cancel_count: int = 0
    pause_count: int = 0
    resume_count: int = 0
    verification_count: int = 0
    fail_upload: bool = True
    fail_create: bool = True
    hold_create: bool = False
    pending_create: Any = None
    source_requests: list[dict[str, Any]] = field(default_factory=list)
    event_queries: list[tuple[str, int]] = field(default_factory=list)
    stream_queries: list[tuple[str, int]] = field(default_factory=list)
    create_bodies: list[dict[str, Any]] = field(default_factory=list)
    expected_failures: set[str] = field(default_factory=set)
    unexpected: list[str] = field(default_factory=list)

    def json(self, route: Any, value: Any, status: int = 200) -> None:
        if status >= 400:
            self.expected_failures.add(route.request.url)
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value, ensure_ascii=False))

    def snapshot_summary(self, value: dict[str, Any]) -> dict[str, Any]:
        return {key: value[key] for key in ("id", "name", "created_at", "archive_sha256", "source", "project_id")} | {
            "file_count": len(value["files"]), "unit_count": 2, "warning_count": len(value["warnings"])}

    def projects(self) -> list[dict[str, Any]]:
        items = []
        for project_id, name in self.project_names.items():
            snapshots = [value for value in self.snapshot_records.values() if value.get("project_id") == project_id]
            runs = [value for value in self.runs.values() if value.get("project_id") == project_id]
            findings = [value for value in self.ledger_records.values() if value["project_id"] == project_id]
            counts = {key: sum(value.get("verification_status") == key for value in findings)
                      for key in ("verified", "rejected", "unverified", "inconclusive", "not_applicable", "environment_unavailable", "stale")}
            counts.update(total=len(findings), open=sum(value["disposition"] == "open" for value in findings),
                          withdrawn=sum(value["disposition"] in {"retracted", "duplicate", "superseded"} for value in findings))
            latest = max(snapshots, key=lambda value: value["created_at"], default=None)
            items.append({"id": project_id, "name": name, "content_key": project_id.ljust(64, "c"),
                          "target_profile": "unknown", "created_at": STAMP, "updated_at": latest["created_at"] if latest else STAMP,
                          "snapshot_count": len(snapshots), "run_count": len(runs),
                          "active_run_count": sum(value["status"] in ACTIVE for value in runs),
                          "latest_snapshot_id": latest["id"] if latest else None,
                          "latest_run_id": runs[-1]["id"] if runs else None, "finding_counts": counts})
        return items

    def source_run(self, run_id: str | None) -> dict[str, Any] | None:
        value = self.runs.get(run_id or "")
        return {key: value.get(key) for key in ("id", "snapshot_id", "snapshot_name", "status", "created_at")} if value else None

    def ledger_summary(self, value: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(value) | {"project_name": self.project_names[value["project_id"]],
            "origin_run": self.source_run(value.get("origin_run_id")), "last_run": self.source_run(value.get("last_run_id"))}

    def ledger_detail(self, value: dict[str, Any]) -> dict[str, Any]:
        sources = list(dict.fromkeys([value["origin_run_id"], value["last_run_id"]]))
        history = []
        for index, run_id in enumerate(sources):
            source = self.source_run(run_id)
            history.append({"run_id": run_id, "run_finding_id": value["origin_finding_id"] if index == 0 else value["last_finding_id"],
                            "relation": "created" if index == 0 else "rediscovered", "revision": value["revision"], "created_at": STAMP,
                            "snapshot_id": source["snapshot_id"] if source else None, "snapshot_name": source["snapshot_name"] if source else None,
                            "run_status": source["status"] if source else None})
        verifications = copy.deepcopy(self.ledger_verifications.get(value["id"], []))
        return {"finding": copy.deepcopy(value), "project": next(item for item in self.projects() if item["id"] == value["project_id"]),
                "origin_run": self.source_run(value["origin_run_id"]), "last_run": self.source_run(value["last_run_id"]),
                "history": history, "verifications": verifications,
                "current_verification": verifications[-1] if verifications and value["verification_status"] != "stale" else None,
                "poc_finding_id": value["origin_finding_id"] if value.get("poc") else None,
                "poc_download_path": f"/api/findings/{value['origin_finding_id']}/poc" if value.get("poc") else None}

    def release_reads(self) -> None:
        pending, self.pending_reads = self.pending_reads, []
        self.held_paths.clear()
        for route in pending:
            self.handle(route)

    def config(self) -> dict[str, Any]:
        selected = next(item for item in self.model_profiles if item["id"] == self.selected_profile_id)
        public = copy.deepcopy(self.model_profiles)
        for item in public:
            item["selected"] = item["id"] == self.selected_profile_id
        value = {"configured": selected["api_key_configured"], "model": selected["model"], "base_url": selected["base_url"],
                 "thinking": "disabled", "missing": [], "selected_profile_id": self.selected_profile_id, "model_profiles": public,
                 "version": "ui-codeagent-smoke", "worker": {"name": "fixture-worker", "busy": False, "alive": True},
                 "budgets": BUDGET, "budget_limits": {"defaults": BUDGET},
                 "run_budget_limits": {"defaults": RUN_LIMITS,
                                       "profiles": {"coverage_review": FULL_RUN_LIMITS, "goal": RUN_LIMITS},
                                       "min": {"responses": 1, "tools": 0, "seconds": 30},
                                       "max": {"responses": 4096, "tools": 32768, "seconds": 14400}},
                 "agent_policy": {"code_bytes": 4096, "code_output_bytes": 24576},
                 "model_health": {"status": "ok", "fails": 0, "trips": 0, "cooldown_seconds": 0}}
        self.config_responses.append(copy.deepcopy(value))
        return value

    def finish_create(self) -> None:
        route = self.pending_create
        self.pending_create = None
        assert route is not None, "no held create request"
        self.respond_create(route)

    def respond_create(self, route: Any) -> None:
        if self.fail_create:
            self.fail_create = False
            self.json(route, {"detail": "模拟队列暂时不可用，请重试"}, 503)
            return
        body = self.create_bodies[-1]
        created = run(CREATED_ID, "running")
        created.update(snapshot_id=body["snapshot_id"], snapshot_name=self.snapshot_records[body["snapshot_id"]]["name"],
                       project_id=self.snapshot_records[body["snapshot_id"]]["project_id"],
                       task_spec=copy.deepcopy(TASK) | body["task"], budgets=body["budgets"],
                       run_limits=body["run_limits"], poc_mode=body["poc_mode"])
        self.runs[CREATED_ID] = created
        self.extra_events[CREATED_ID] = []
        self.findings[CREATED_ID] = finding(CREATED_ID)
        self.json(route, copy.deepcopy(created))

    def profile_api(self, route: Any, parts: list[str], method: str) -> None:
        if any(item["status"] in ACTIVE for item in self.runs.values()):
            self.json(route, {"detail": "当前有排队、执行或暂停中的审计，请先结束或取消。"}, 409)
            return
        profile_id = parts[2] if len(parts) > 2 else ""
        current = next((item for item in self.model_profiles if item["id"] == profile_id), None)
        body = route.request.post_data_json if method in {"POST", "PUT"} else {}
        self.profile_requests.append((method, profile_id, body))
        if method == "POST" and len(parts) == 2:
            profile_id = f"profile-created-{len(self.model_profiles)}"
            current = {"id": profile_id, "credential_source": "stored", "ordinal": len(self.model_profiles), "created_at": STAMP}
            self.model_profiles.append(current)
        elif current is None:
            self.json(route, {"detail": "模型配置档案不存在"}, 404)
            return
        elif len(parts) == 4 and parts[3] == "select":
            self.selected_profile_id = profile_id
            self.json(route, self.config())
            return
        elif current["credential_source"] == "environment" or method == "DELETE" and profile_id == self.selected_profile_id:
            self.json(route, {"detail": "不能修改环境变量档案或删除当前档案。"}, 409)
            return
        if method == "DELETE":
            self.model_profiles.remove(current)
            self.key_fingerprints.pop(profile_id, None)
            route.fulfill(status=204, body="")
            return
        for key in ("label", "model", "base_url"):
            current[key] = body[key]
        if "api_key" in body:
            self.key_fingerprints[profile_id] = hashlib.sha256(body["api_key"].encode()).hexdigest() if body["api_key"] else ""
        current.update(api_key_configured=bool(self.key_fingerprints.get(profile_id)), updated_at=STAMP)
        self.json(route, self.config(), 201 if method == "POST" else 200)

    def handle(self, route: Any) -> None:
        request = route.request
        url = urlsplit(request.url)
        path, query, method = url.path.removeprefix("/api"), parse_qs(url.query), request.method
        parts = path.strip("/").split("/")
        if method == "GET":
            self.read_counts[path] = self.read_counts.get(path, 0) + 1
        if method == "GET" and path in self.held_paths:
            self.pending_reads.append(route)
            return
        if method == "GET" and self.read_failures.get(path, 0):
            self.read_failures[path] -= 1
            self.json(route, {"detail": "模拟读取暂时失败，请重试"}, 503)
            return
        if method == "GET" and path == "/config":
            self.json(route, self.config())
        elif method == "GET" and path == "/poc/readiness":
            self.json(route, {"available": False, "reason": "unsupported_target", "message": "离线界面夹具不连接验证靶场。",
                              "checked_at": STAMP, "capabilities": {"supported_targets": ["lab30"], "browser": False,
                                                                     "verification_contexts": True}})
        elif parts[:2] == ["config", "profiles"]:
            self.profile_api(route, parts, method)
        elif method == "GET" and path == "/snapshots":
            self.json(route, [self.snapshot_summary(value) for value in self.snapshot_records.values()])
        elif method == "POST" and path == "/snapshots":
            self.upload_count += 1
            if self.fail_upload:
                self.fail_upload = False
                self.json(route, {"detail": "模拟 ZIP 导入失败，请重新选择"}, 422)
            else:
                value = copy.deepcopy(self.upload_result or snapshot())
                self.snapshot_records[value["id"]] = value
                self.json(route, value | {"project": next(item for item in self.projects() if item["id"] == value["project_id"]),
                                         "project_reused": self.upload_project_reused, "snapshot_reused": self.upload_result is None})
        elif method == "GET" and len(parts) == 2 and parts[0] == "snapshots" and parts[1] in self.snapshot_records:
            snapshot_id = parts[1]
            if self.snapshot_read_failures.get(snapshot_id, 0):
                self.snapshot_read_failures[snapshot_id] -= 1
                self.json(route, {"detail": "模拟快照读取暂时失败，请重试"}, 503)
            else:
                self.json(route, self.snapshot_records[snapshot_id])
        elif method == "GET" and len(parts) == 3 and parts[0] == "snapshots" and parts[1] in self.snapshot_records and parts[2] == "source":
            snapshot_id = parts[1]
            start, end = int(query.get("start", ["1"])[0]), int(query.get("end", ["200"])[0])
            source_path = query.get("path", [SOURCE_PATH])[0]
            self.source_requests.append({"snapshot_id": snapshot_id, "path": source_path, "start": start, "end": end})
            assert 0 < end - start + 1 <= 400, "source request exceeds server's line window"
            self.json(route, {"snapshot_id": snapshot_id, "path": source_path, "sha256": "b" * 64,
                              "lines": [{"number": number, "text": "<?php" if number == 1 else "$name = $_GET['name'];" if number == 10 else "file_put_contents($base . $name, $content);" if number == 12 else f"// 原始源码第 {number} 行"} for number in range(start, end + 1)]})
        elif method == "GET" and path == "/projects":
            self.json(route, self.projects())
        elif method == "GET" and parts[0] == "projects" and len(parts) >= 2:
            project = next((item for item in self.projects() if item["id"] == parts[1]), None)
            if project is None:
                self.json(route, {"detail": "Project does not exist"}, 404)
            elif len(parts) == 2:
                self.json(route, project | {"snapshots": [self.snapshot_summary(item) for item in self.snapshot_records.values() if item.get("project_id") == parts[1]],
                                           "runs": [item for item in self.runs.values() if item.get("project_id") == parts[1]],
                                           "findings": [item for item in self.ledger_records.values() if item["project_id"] == parts[1]]})
            elif parts[2] == "runs":
                self.json(route, [item for item in self.runs.values() if item.get("project_id") == parts[1]])
            elif parts[2] == "findings":
                self.json(route, [item for item in self.ledger_records.values() if item["project_id"] == parts[1]])
            else:
                self.unexpected.append(f"{method} {path}")
                self.json(route, {"detail": "Unhandled project fixture"}, 501)
        elif method == "GET" and path == "/project-findings":
            filters = {key: values[0] for key, values in query.items()}
            self.ledger_queries.append(filters)
            items = list(self.ledger_records.values())
            for key in ("project_id", "severity", "verification_status"):
                if filters.get(key):
                    items = [item for item in items if item.get(key) == filters[key]]
            disposition = filters.get("disposition", "")
            if disposition and disposition != "all":
                items = [item for item in items if item["disposition"] == disposition]
            elif disposition != "all":
                items = [item for item in items if item["disposition"] not in {"retracted", "duplicate", "superseded"}]
            if filters.get("q"):
                needle = filters["q"].casefold()
                items = [item for item in items if needle in " ".join(str(item.get(key) or "") for key in ("title", "summary", "file_path", "project_name")).casefold()]
            items.sort(key=lambda item: (item["updated_at"], item["id"]), reverse=True)
            offset, limit = int(filters.get("offset", 0)), int(filters.get("limit", 25))
            self.json(route, {"items": [self.ledger_summary(item) for item in items[offset:offset + limit]],
                              "total": len(items), "offset": offset, "limit": limit})
        elif method == "GET" and len(parts) == 2 and parts[0] == "project-findings":
            value = self.ledger_records.get(parts[1])
            self.json(route, self.ledger_detail(value) if value else {"detail": "Project finding does not exist"}, 200 if value else 404)
        elif method == "GET" and path == "/runs":
            self.json(route, list(reversed(list(self.runs.values()))))
        elif method == "POST" and path == "/runs":
            body = request.post_data_json
            assert "scope" not in body, "codeagent forbids the legacy scope field"
            assert set(body) == {"snapshot_id", "budgets", "run_limits", "poc_mode", "task"}, f"unexpected create fields: {set(body)}"
            assert set(body["run_limits"]) == {"responses", "tools", "seconds"}
            assert body["poc_mode"] in {"off", "auto", "required"}
            self.create_count += 1
            self.create_bodies.append(body)
            if self.hold_create:
                self.pending_create = route
            else:
                self.respond_create(route)
        elif len(parts) == 2 and parts[0] == "runs" and method == "GET" and parts[1] in self.runs:
            item = self.runs[parts[1]]
            project = next((value for value in self.projects() if value["id"] == item.get("project_id")), None)
            self.json(route, detail(item, self.findings[parts[1]]) | {"project": project,
                "project_findings": [value for value in self.ledger_records.values() if value["project_id"] == item.get("project_id")],
                "carried_findings": [], "finding_relations": []} | copy.deepcopy(self.detail_overrides.get(parts[1], {})))
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] == "final-review" and method == "GET":
            # These fixtures predate Planner v2.  The real endpoint answers 409 and the
            # report page hides the fact package instead of inventing one.
            self.json(route, {"detail": "This run predates Planner v2; it keeps its historical report layout"}, 409)
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] in {"project-map", "project-overview"}:
            self.json(route, project_map(self.runs[parts[1]]))
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] in {"events", "event-log"}:
            run_id, after = parts[1], int(query.get("after", ["0"])[0])
            items = self.event_overrides.get(run_id, events(run_id, run_id == COMPLETED_ID)) + self.extra_events.get(run_id, [])
            if parts[2] == "event-log":
                self.event_queries.append((run_id, after))
                batch = [item for item in items if item["id"] > after][:2000]
                if after and batch:
                    previous = next((item for item in items if item["id"] == after), None)
                    if previous:
                        batch.insert(0, previous)
                self.json(route, {"events": batch, "remaining": sum(item["id"] > after for item in items)})
            else:
                self.stream_queries.append((run_id, after))
                frames = [item for item in items if item["id"] > after]
                if len(frames) > 1:
                    frames.insert(2, frames[1])
                body = "retry: 60000\n\n" + "".join(f"id: {item['id']}\ndata: {json.dumps(item, ensure_ascii=False)}\n\n" for item in frames)
                route.fulfill(status=200, content_type="text/event-stream", headers={"Cache-Control": "no-cache"}, body=body)
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] in {"pause", "resume", "cancel"} and method == "POST":
            item, action = self.runs[parts[1]], parts[2]
            allowed = {"pause": {"pending", "running"}, "resume": {"paused"}, "cancel": ACTIVE}
            if item["status"] not in allowed[action]:
                self.json(route, {"detail": f"Run is already {item['status']}"}, 409)
                return
            setattr(self, f"{action}_count", getattr(self, f"{action}_count") + 1)
            item["status"] = {"pause": "paused", "resume": "running", "cancel": "cancelled"}[action]
            item["finished_at"] = STAMP if action == "cancel" else None
            extra = self.extra_events.setdefault(item["id"], [])
            extra.append(event(item["id"], 12 + len(extra), {"pause": "run_paused", "resume": "run_resumed", "cancel": "run_cancelled"}[action], {"reason": f"user_{action}"}))
            self.json(route, copy.deepcopy(item))
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] == "report" and method == "GET":
            self.json(route, detail(self.runs[parts[1]], self.findings[parts[1]]) | copy.deepcopy(self.detail_overrides.get(parts[1], {})))
        elif len(parts) == 3 and parts[0] == "findings" and parts[2] == "verifications" and method == "POST":
            self.verification_count += 1
            item = next(value for value in self.findings.values() if value["id"] == parts[1])
            item["verdict"] = "confirmed"
            item["verifications"].append({"id": "verification-smoke", "created_at": STAMP, "verdict": "confirmed", "execution_status": "not_run",
                                          "notes": "已核对原始源码及上下文。", "modified_script": "", "modification_notes": "", "target_version": "fixture-commit",
                                          "command": "", "expected_result": "", "normal_observation": "", "attack_observation": "", "browser_execution": False, "files": []})
            run_id = item["run_id"]
            extra = self.extra_events.setdefault(run_id, [])
            next_id = max(row["id"] for row in events(run_id, run_id == COMPLETED_ID) + extra) + 1
            extra.append(event(run_id, next_id, "verification_recorded", {"role": "host", "finding_id": item["id"], "verdict": "confirmed"}))
            self.json(route, copy.deepcopy(item))
        else:
            self.unexpected.append(f"{method} {path}")
            self.json(route, {"detail": f"Unhandled UI fixture: {method} {path}"}, 501)


def sources_api() -> MockAPI:
    """Several source identities, re-zipped snapshots, and a paginated shared ledger."""
    api = MockAPI(fail_create=False, fail_upload=False)
    api.project_names.update({OTHER_PROJECT_ID: "另一个认证项目", EMPTY_PROJECT_ID: "尚未审计的源码"})
    newer = snapshot()
    newer.update(id=NEWER_SNAPSHOT_ID, name="审计样例源码-重新打包.zip", created_at="2026-10-20T09:30:00+00:00", archive_sha256="d" * 64)
    other = snapshot()
    other.update(id=OTHER_SNAPSHOT_ID, name="认证项目.zip", project_id=OTHER_PROJECT_ID,
                 content_key="e" * 64, archive_sha256="e" * 64)
    empty = snapshot()
    empty.update(id="smoke-unreviewed-snapshot", name="未审计源码.zip", project_id=EMPTY_PROJECT_ID,
                 content_key="f" * 64, archive_sha256="f" * 64)
    api.snapshot_records.update({item["id"]: item for item in (newer, other, empty)})
    rediscovered = run("smoke-rediscovered")
    rediscovered.update(snapshot_id=NEWER_SNAPSHOT_ID, snapshot_name=newer["name"])
    api.runs[rediscovered["id"]] = rediscovered
    api.findings[rediscovered["id"]] = finding(rediscovered["id"])
    api.findings[rediscovered["id"]]["project_finding_id"] = LEDGER_ID
    api.findings[COMPLETED_ID]["project_finding_id"] = LEDGER_ID
    api.ledger_records[LEDGER_ID].update(last_run_id=rediscovered["id"], last_finding_id=f"finding-{rediscovered['id']}",
                                         updated_at="2026-10-20T10:30:00+00:00")
    stale = ledger_finding(STALE_LEDGER_ID)
    stale.update(title="结论修订后需要重新验证", severity="high", revision=3,
                 verification_status="stale", verification_verdict=None, updated_at="2026-10-20T10:00:00+00:00",
                 last_run_id=rediscovered["id"], last_finding_id=f"finding-{rediscovered['id']}")
    api.ledger_records[STALE_LEDGER_ID] = stale
    api.ledger_verifications[STALE_LEDGER_ID] = [verification_record(STALE_LEDGER_ID)]
    for index in range(28):
        item = ledger_finding(f"ledger-page-{index:02}")
        item.update(title=f"待核查数据流 {index:02}", severity="unknown" if index == 27 else "low", verification_status="unverified", verification_verdict=None,
                    poc=None, updated_at=f"2026-10-19T08:{index:02}:00+00:00")
        api.ledger_records[item["id"]] = item
    withdrawn = ledger_finding("ledger-withdrawn")
    withdrawn.update(title="已撤回的历史推测", disposition="retracted", severity="high", verification_status="unverified", poc=None)
    api.ledger_records[withdrawn["id"]] = withdrawn
    other_finding = ledger_finding("ledger-other-project")
    other_finding.update(project_id=OTHER_PROJECT_ID, project_name=api.project_names[OTHER_PROJECT_ID],
                         title="认证边界缺少权限校验", severity="critical", verification_status="not_applicable", verification_verdict=None,
                         origin_run_id="missing-historical-run", last_run_id="missing-historical-run", poc=None,
                         evidence=[{"snapshot_id": "", "path": "src/auth.php", "start_line": 8, "end_line": 9}])
    api.ledger_records[other_finding["id"]] = other_finding
    return api
