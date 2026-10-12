#!/usr/bin/env python3
"""Run one unit through the real agent and print every turn and tool call.

This calls audit_unit itself — no tool code is duplicated here — so what it shows is
exactly what an audit run does.

Usage: demo_trace.py <snapshot-id> <file-suffix> [prompt-id] [responses] [tools]
"""
import asyncio
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from audit.agent import audit_unit  # noqa: E402
from audit.config import Settings, find_env_file, load_env_file  # noqa: E402
from audit.db import Store  # noqa: E402
from audit.evidence import seen_ranges, validate_evidence  # noqa: E402
from audit.prompts import system_prompt  # noqa: E402
from audit.source import SourceRepository  # noqa: E402

load_env_file(find_env_file(BACKEND))
settings = Settings.load()
repository = SourceRepository(settings.data_dir)
store = Store(settings.db_path)

snapshot_id = sys.argv[1]
suffix = sys.argv[2]
prompt_id = sys.argv[3] if len(sys.argv) > 3 else "P2"
responses = int(sys.argv[4]) if len(sys.argv) > 4 else 8
tools = int(sys.argv[5]) if len(sys.argv) > 5 else 16

snapshot = repository.get_snapshot(snapshot_id)
unit = next(u for u in snapshot["units"] if u["file_path"].endswith(suffix))
prompt = store.get_prompt(prompt_id)
budgets = {"responses": responses, "tools": tools, "seconds": 300}

print(f"unit {unit['id'][:10]}  {unit['file_path']}:{unit['start_line']}-{unit['end_line']}"
      f"  [{unit['kind']}] {unit['symbol']}  slice {unit['slice_index']}/{unit['slice_count']}")
print(f"prompt {prompt_id} ({prompt['label']})  budgets {budgets}\n")


def on_event(event: dict) -> None:
    if "turn" in event:
        args = json.dumps(event["args"], ensure_ascii=False)
        print(f"  [{event['turn']:>2}] -> {event['tool']}({args[:200]})")
    elif "chars" in event:
        print(f"       <- {event['tool']}: {event['chars']} chars | {event['preview'][:120]!r}")
    elif "retry" in event:
        print(f"       !! output rejected, retrying: {event['retry'][:200]}")
    elif event.get("final"):
        print("       == final structured output")


async def main() -> int:
    outcome = await audit_unit(
        repository=repository,
        snapshot_id=snapshot_id,
        snapshot_name=snapshot["name"],
        unit=unit,
        prompt_text=system_prompt(prompt["text"]),
        config=settings.model,
        budgets=budgets,
        on_event=on_event,
    )
    if outcome["error"]:
        print(f"\n!! incomplete={outcome['incomplete']}: {outcome['error'][:300]}")
    print(f"\nusage: {outcome['usage']}  repeated tool calls refused: {outcome['repeats']}")

    analysis = outcome["analysis"]
    if analysis is None:
        print("no structured output produced")
        return 0

    file_lines = {item["path"]: item["line_count"] for item in snapshot["files"]}
    ranges = seen_ranges(unit, outcome["seen"])
    print(f"summary: {analysis.summary[:400]}\n")
    for name, check in analysis.by_category().items():
        evidence = [ref.model_dump() for ref in check.evidence]
        problems = validate_evidence(evidence, file_lines, ranges) if check.conclusion == "candidate" else []
        print(f"  {name:<20} conclusion={check.conclusion:<20} severity={check.severity or '-'}")
        if check.reasoning:
            print(f"      reasoning: {check.reasoning[:400]}")
        if check.conclusion == "candidate":
            print(f"      input_source: {check.input_source[:200]}")
            print(f"      propagation : {check.propagation[:200]}")
            print(f"      danger      : {check.dangerous_operation[:200]}")
            print(f"      protection  : {(check.protection or '-')[:200]}")
            print(f"      evidence    : {[(e['path'], e['start_line'], e['end_line']) for e in evidence]}")
            print(f"      evidence ok : {'YES' if not problems else problems}")
            print(f"      poc lines   : {len((check.poc.script if check.poc else '') or '')}")
        if check.missing_context:
            print(f"      missing     : {check.missing_context[:200]}")
    return 0


raise SystemExit(asyncio.run(main()))
