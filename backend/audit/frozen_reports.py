"""Materialize once from terminal inputs; all exports reuse identical saved bytes."""
from __future__ import annotations

import base64

from .report_bundle import build_and_render
from .report import render_json, render_zip


def materialize(store, repository, run_id):
    frozen = store.frozen_report(run_id)
    if frozen is None or frozen["facts"] is not None:
        return frozen
    payload = dict(frozen["input"])
    evidence = [(item["name"], base64.b64decode(item["data"])) for item in payload.pop("frozen_evidence", [])]
    records = payload.pop("all_records")
    payload["frozen_input_hash"] = frozen["input_hash"]
    facts, markdown = build_and_render(payload, all_records=records, repository=repository,
                                       generated_at=payload["generated_at"])
    payload.update(final_review=facts, report_quality=facts["quality_result"], report_markdown=markdown)
    json_export = render_json(payload)
    zip_blob = render_zip(payload, evidence)
    return store.store_report_rendering(run_id, facts, markdown, zip_blob, json_export)
