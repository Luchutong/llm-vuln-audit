#!/usr/bin/env python3
"""Decisive test: can the model produce the structured verdict with NO tools at all?

The source is inlined, so there is nothing to explore. If it still will not answer,
no tool budget will ever be enough and the answer must be forced by a tool-free call.

Usage: demo_no_tools.py <snapshot-id> <file-suffix> [prompt-id]
"""
import asyncio
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.settings import ModelSettings  # noqa: E402

from audit.agent import build_model, render_unit  # noqa: E402
from audit.config import Settings, find_env_file, load_env_file  # noqa: E402
from audit.db import Store  # noqa: E402
from audit.prompts import system_prompt  # noqa: E402
from audit.schemas import UnitAnalysis  # noqa: E402
from audit.source import SourceRepository  # noqa: E402
from audit.evidence import seen_ranges, validate_evidence  # noqa: E402

load_env_file(find_env_file(BACKEND))
settings = Settings.load()
repository = SourceRepository(settings.data_dir)
store = Store(settings.db_path)

snapshot_id = sys.argv[1]
suffix = sys.argv[2]
prompt_id = sys.argv[3] if len(sys.argv) > 3 else "P2"

snapshot = repository.get_snapshot(snapshot_id)
unit = next(u for u in snapshot["units"] if u["file_path"].endswith(suffix))
prompt = store.get_prompt(prompt_id)

# No tools, no deps, no event stream: one call, one structured answer.
agent = Agent(
    build_model(settings.model),
    output_type=UnitAnalysis,
    instructions=system_prompt(prompt["text"]),
    model_settings=ModelSettings(extra_body=settings.model.extra_body()),
    retries=1,
)

message = render_unit(unit, snapshot["name"], None) + (
    "\n\n本单元没有任何工具可用：上面就是你全部可依据的代码。"
    "请直接给出三类的结构化结论；证据行号必须落在上面给出的行范围内。"
)


async def main() -> int:
    started = time.time()
    seen: list[str] = []

    def handler(_ctx, event_stream):
        async def consume():
            async for event in event_stream:
                kind = getattr(event, "event_kind", "")
                part = getattr(event, "part", None)
                part_kind = getattr(part, "part_kind", "")
                if kind == "part_start" and part_kind in ("retry-prompt", "tool-call", "final-result"):
                    seen.append(f"[{part_kind}] {str(part)[:1500]}")
                elif kind and kind != "part_start":
                    seen.append(f"[{kind}] {str(event)[:600]}")
        return consume()

    try:
        result = await agent.run(message, event_stream_handler=handler)
    except Exception as exc:
        print(f"!! {type(exc).__name__}: {str(exc)[:400]}\n")
        for line in seen:
            print(line, "\n")
        return 1
    elapsed = time.time() - started
    usage = result.usage
    print(f"prompt {prompt_id}  {elapsed:.1f}s  requests={usage.requests} "
          f"in={usage.input_tokens} out={usage.output_tokens}\n")

    analysis = result.output
    file_lines = {item["path"]: item["line_count"] for item in snapshot["files"]}
    ranges = seen_ranges(unit, [])
    print(f"summary: {analysis.summary[:300]}\n")
    for name, check in analysis.by_category().items():
        evidence = [ref.model_dump() for ref in check.evidence]
        print(f"  {name:<20} conclusion={check.conclusion:<20} severity={check.severity or '-'}")
        if check.reasoning:
            print(f"      {check.reasoning[:300]}")
        if check.conclusion == "candidate":
            print(f"      danger   : {check.dangerous_operation[:160]}")
            print(f"      evidence : {[(e['path'], e['start_line'], e['end_line']) for e in evidence]}")
            print(f"      validated: {validate_evidence(evidence, file_lines, ranges) or 'OK'}")
        if check.missing_context:
            print(f"      missing  : {check.missing_context[:160]}")
    return 0


raise SystemExit(asyncio.run(main()))
