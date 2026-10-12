#!/usr/bin/env python3
"""Isolate the failure: is the model unable to answer, or unable to answer *at this size*?

Runs the same unit with progressively smaller output schemas, no tools.
"""
import asyncio
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from pydantic import BaseModel, Field  # noqa: E402
from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.settings import ModelSettings  # noqa: E402

from audit.agent import build_model, render_unit  # noqa: E402
from audit.config import Settings, find_env_file, load_env_file  # noqa: E402
from audit.db import Store  # noqa: E402
from audit.prompts import system_prompt  # noqa: E402
from audit.schemas import UnitAnalysis  # noqa: E402
from audit.source import SourceRepository  # noqa: E402


class Tiny(BaseModel):
    """Smallest possible verdict: one category, no evidence, no POC."""

    conclusion: str = Field(description="candidate / no_candidate / insufficient_context")
    reasoning: str = Field(description="一句话依据")


class ThreeTiny(BaseModel):
    """Three categories, still no evidence, no POC."""

    sqli: Tiny
    xss_r: Tiny
    command_injection: Tiny


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
base = render_unit(unit, snapshot["name"], None)


async def attempt(label: str, schema) -> None:
    agent = Agent(
        build_model(settings.model),
        output_type=schema,
        instructions=system_prompt(prompt["text"]),
        model_settings=ModelSettings(extra_body=settings.model.extra_body()),
        retries=1,
    )
    try:
        result = await agent.run(base)
    except Exception as exc:
        print(f"{label:<28} FAILED  {type(exc).__name__}: {str(exc)[:120]}")
        return
    usage = result.usage
    out = result.output
    dump = out.model_dump() if hasattr(out, "model_dump") else out
    print(f"{label:<28} OK      out_tokens={usage.output_tokens}  {str(dump)[:160]}")


async def main() -> int:
    await attempt("tiny: 1 category", Tiny)
    await attempt("tiny: 3 categories", ThreeTiny)
    await attempt("full: UnitAnalysis (POC etc)", UnitAnalysis)
    return 0


raise SystemExit(asyncio.run(main()))
