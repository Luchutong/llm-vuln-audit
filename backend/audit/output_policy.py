"""Versioned model output contract; canonical stored facts keep their old shape."""
from __future__ import annotations

import copy
import json

POLICY = "audit-evidence-v1"


def enabled(task):
    return (task or {}).get("output_policy") == POLICY


def _payload(value):
    if isinstance(value, str):
        value = json.loads(value)
    elif hasattr(value, "model_dump"):
        value = value.model_dump()
    return copy.deepcopy(value)


def worker_payload(value, task):
    if not enabled(task):
        return value
    value = _payload(value)
    if isinstance(value, dict) and "reasoning" not in value:
        # A compatibility alias, not a second model-authored interpretation.
        # The original summary still goes through the normal typed validation.
        value["reasoning"] = value.get("summary")
    return value


def planner_payload(value, task):
    if not enabled(task):
        return value
    value = _payload(value)
    if isinstance(value, dict):
        for field in ("report", "next_action"):
            value.pop(field, None)
    return value


def _remove(schema, fields):
    for field in fields:
        schema.get("properties", {}).pop(field, None)
    if "required" in schema:
        schema["required"] = [field for field in schema["required"] if field not in fields]


def prune_defs(schema):
    """Keep only transitively referenced definitions after removing output fields."""
    defs = schema.get("$defs", {})
    used = set()
    def visit(node):
        if isinstance(node, dict):
            ref = node.get("$ref", "")
            if ref.startswith("#/$defs/"):
                name = ref.removeprefix("#/$defs/")
                if name not in used:
                    used.add(name)
                    visit(defs.get(name))
            for key, value in node.items():
                if key != "$defs":
                    visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)
    visit(schema)
    if defs:
        schema["$defs"] = {key: value for key, value in defs.items() if key in used}
    return schema


def worker_schema(schema, task):
    if not enabled(task):
        return schema
    _remove(schema, {"reasoning"})
    schema["properties"]["summary"]["description"] = (
        "唯一的简短结果依据：当前结论、实际源码事实及缺口；不重复 findings 或 direction_results。")
    fields = {"remediation", "retest", "severity"}
    if not task.get("require_poc", True):
        fields.add("poc")
    _remove(schema["$defs"]["TaskFinding"], fields)
    for example in schema.get("examples", []):
        example.pop("reasoning", None)
        for finding in example.get("findings", []):
            for field in fields:
                finding.pop(field, None)
    return prune_defs(schema)


def planner_schema(schema, task):
    if not enabled(task):
        return schema
    _remove(schema, {"report", "next_action"})
    return prune_defs(schema)


WORKER_INSTRUCTION = (
    "\n输出政策 audit-evidence-v1：summary 是唯一的工作项结果依据，省略 reasoning；"
    "宿主将同一段 summary 兼容写入旧 reasoning 字段。保留实际源码引用、根因链、利用前提、"
    "方向结果、反证、缺口和必要的后续工作；省略 remediation、retest 和 severity。"
    "报告由宿主用冻结事实生成，无需撰写交付散文。")
PLANNER_INSTRUCTION = (
    "\n输出政策 audit-evidence-v1：只提交调度、补证与审查所需的结构化决策和简短 basis_summary；"
    "省略 report 与 next_action。审计报告由宿主从冻结事实生成。")
