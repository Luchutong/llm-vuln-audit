"""In-memory codeagent API for browser checks; no audit or provider is contacted."""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

STAMP = "2026-10-20T08:30:00+00:00"
SNAPSHOT_ID = "smoke-snapshot"
COMPLETED_ID = "smoke-completed"
CREATED_ID = "smoke-created"
SOURCE_PATH = "src/upload.php"
OBJECTIVE = "检查上传入口到文件写入的安全边界并提供源码证据。"
CRITERIA = "引用输入来源、传播路径和敏感操作的原始行号；无法确认时说明缺失上下文。"
LONG_VALUE = "LONG_PAYLOAD_START\n" + "工具返回的长文本与无空格路径/" * 700 + "\nLONG_PAYLOAD_END"
LONG_LOG = "PRINT_LOG_START\n" + "已读取的源码观察与批处理日志。\n" * 600 + "PRINT_LOG_END\n[日志已截断]"
BUDGET = {"responses": 24, "tools": 96, "seconds": 1800}
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
            "scope": [], "scope_mode": "snapshot", "model": "ui-fixture-model",
            "model_profile": {"profile_id": "profile-environment", "model": "ui-fixture-model", "base_url": "http://fixture.invalid/v1"},
            "budgets": copy.deepcopy(BUDGET), "task_spec": copy.deepcopy(TASK), "status": status,
            "created_at": STAMP, "started_at": STAMP, "finished_at": None if status in ACTIVE else STAMP,
            "usage": copy.deepcopy(USAGE), "total_tasks": 1, "completed_tasks": int(status == "completed")}


def finding(run_id: str) -> dict[str, Any]:
    return {"id": f"finding-{run_id}", "run_id": run_id, "task_id": "task-upload", "task_key": "upload-boundary",
            "fingerprint": "fixture-fingerprint", "category": "task_goal", "finding_kind": "source_observation",
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
            "findings": [copy.deepcopy(observed)], "units": [], "goals": [], "work_items": [], "attributions": [],
            "metrics": {"candidates": candidate, "candidate_findings": candidate, "discarded_candidates": 0, "withdrawn_findings": int(withdrawn),
                        "confirmed": int(observed["verdict"] == "confirmed"), "rejected": 0, "uncertain": int(observed["verdict"] != "confirmed"),
                        "awaiting_verification": 0, "audit_coverage": float(done), "task_coverage": float(done), "verification_coverage": 0,
                        "total_units": 0, "completed_units": 0, "incomplete_units": 0, "pending_units": 0, "total_tasks": 1,
                        "completed_tasks": int(done), "terminal_tasks": int(done), "active_tasks": int(not done),
                        "truth_status": "planner_goal_not_comparable", "evaluation": None}}


def event(run_id: str, number: int, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(payload)
    role = payload.setdefault("role", "planner" if kind.startswith("planner_") else "host" if kind.startswith("run_") else "worker")
    if role in {"planner", "recon"}:
        payload.update(plan_id="plan-smoke", session_id="session-smoke")
    if role == "worker":
        payload.update(task_id="task-upload", task_key="upload-boundary", worker_id="worker-1", attempt=1)
    return {"id": number, "run_id": run_id, "unit_id": "task-upload" if role == "worker" else None,
            "kind": kind, "payload": payload, "created_at": STAMP}


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


@dataclass
class MockAPI:
    """Strict router: unhandled API calls fail locally and never reach a real service."""
    snapshot_records: dict[str, dict[str, Any]] = field(default_factory=lambda: {SNAPSHOT_ID: snapshot()})
    snapshot_read_failures: dict[str, int] = field(default_factory=dict)
    runs: dict[str, dict[str, Any]] = field(default_factory=lambda: {COMPLETED_ID: run()})
    findings: dict[str, dict[str, Any]] = field(default_factory=lambda: {COMPLETED_ID: finding(COMPLETED_ID)})
    model_profiles: list[dict[str, Any]] = field(default_factory=profiles)
    selected_profile_id: str = "profile-environment"
    # Only hashes are retained to test omission/clearing. Real encryption is covered by backend tests.
    key_fingerprints: dict[str, str] = field(default_factory=lambda: {"profile-secondary": "existing-encrypted-key-fixture"})
    profile_requests: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    config_responses: list[dict[str, Any]] = field(default_factory=list)
    extra_events: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
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

    def config(self) -> dict[str, Any]:
        selected = next(item for item in self.model_profiles if item["id"] == self.selected_profile_id)
        public = copy.deepcopy(self.model_profiles)
        for item in public:
            item["selected"] = item["id"] == self.selected_profile_id
        value = {"configured": selected["api_key_configured"], "model": selected["model"], "base_url": selected["base_url"],
                 "thinking": "disabled", "missing": [], "selected_profile_id": self.selected_profile_id, "model_profiles": public,
                 "version": "ui-codeagent-smoke", "worker": {"name": "fixture-worker", "busy": False, "alive": True},
                 "budgets": BUDGET, "budget_limits": {"defaults": BUDGET}, "agent_policy": {"code_bytes": 4096, "code_output_bytes": 24576},
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
                       task_spec=body["task"], budgets=body["budgets"])
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
        if method == "GET" and path == "/config":
            self.json(route, self.config())
        elif parts[:2] == ["config", "profiles"]:
            self.profile_api(route, parts, method)
        elif method == "GET" and path == "/snapshots":
            self.json(route, [{key: value[key] for key in ("id", "name", "created_at", "archive_sha256", "source")} |
                             {"file_count": len(value["files"]), "unit_count": 2, "warning_count": len(value["warnings"])} for value in self.snapshot_records.values()])
        elif method == "POST" and path == "/snapshots":
            self.upload_count += 1
            if self.fail_upload:
                self.fail_upload = False
                self.json(route, {"detail": "模拟 ZIP 导入失败，请重新选择"}, 422)
            else:
                self.json(route, snapshot())
        elif method == "GET" and len(parts) == 2 and parts[0] == "snapshots" and parts[1] in self.snapshot_records:
            snapshot_id = parts[1]
            if self.snapshot_read_failures.get(snapshot_id, 0):
                self.snapshot_read_failures[snapshot_id] -= 1
                self.json(route, {"detail": "模拟快照读取暂时失败，请重试"}, 503)
            else:
                self.json(route, self.snapshot_records[snapshot_id])
        elif method == "GET" and path == f"/snapshots/{SNAPSHOT_ID}/source":
            start, end = int(query.get("start", ["1"])[0]), int(query.get("end", ["200"])[0])
            source_path = query.get("path", [SOURCE_PATH])[0]
            self.source_requests.append({"path": source_path, "start": start, "end": end})
            assert 0 < end - start + 1 <= 400, "source request exceeds server's line window"
            self.json(route, {"snapshot_id": SNAPSHOT_ID, "path": source_path, "sha256": "b" * 64,
                              "lines": [{"number": number, "text": "<?php" if number == 1 else "$name = $_GET['name'];" if number == 10 else "file_put_contents($base . $name, $content);" if number == 12 else f"// 原始源码第 {number} 行"} for number in range(start, end + 1)]})
        elif method == "GET" and path == "/runs":
            self.json(route, list(reversed(list(self.runs.values()))))
        elif method == "POST" and path == "/runs":
            body = request.post_data_json
            assert "scope" not in body, "codeagent forbids the legacy scope field"
            assert set(body) == {"snapshot_id", "budgets", "task"}, f"unexpected create fields: {set(body)}"
            self.create_count += 1
            self.create_bodies.append(body)
            if self.hold_create:
                self.pending_create = route
            else:
                self.respond_create(route)
        elif len(parts) == 2 and parts[0] == "runs" and method == "GET" and parts[1] in self.runs:
            self.json(route, detail(self.runs[parts[1]], self.findings[parts[1]]))
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] in {"project-map", "project-overview"}:
            self.json(route, project_map(self.runs[parts[1]]))
        elif len(parts) == 3 and parts[0] == "runs" and parts[2] in {"events", "event-log"}:
            run_id, after = parts[1], int(query.get("after", ["0"])[0])
            items = events(run_id, run_id == COMPLETED_ID) + self.extra_events.get(run_id, [])
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
            self.json(route, detail(self.runs[parts[1]], self.findings[parts[1]]))
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
