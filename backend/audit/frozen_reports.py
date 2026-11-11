"""Materialize once from terminal inputs; all exports reuse identical saved bytes."""
from __future__ import annotations

import base64

from .report_bundle import build_and_render
from .report import render_json, render_zip


def materialize(store, repository, run_id):
    frozen = store.frozen_report(run_id)
    if frozen is None or frozen["facts"] is not None:
        return frozen
    from .output_policy import enabled
    if enabled((frozen["input"].get("run") or {}).get("task_spec")):
        from .report_bundle import build_final_review
        from .audit_report import export
        payload = dict(frozen["input"])
        payload["frozen_input_hash"] = frozen["input_hash"]
        facts = build_final_review(payload, all_records=payload.get("all_records"), repository=repository,
                                   generated_at=payload["generated_at"])
        saved = {**frozen, "facts": facts}
        return store.store_report_rendering(run_id, facts, export(saved).decode(),
            export(saved, format="zip"), export(saved, format="json").decode())
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
