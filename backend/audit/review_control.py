"""Durable per-fact publication allowances, independent of batch/round/lease IDs."""
from __future__ import annotations

import json
import re

from pydantic import ValidationError

from .runtime import StopAudit

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_review_allowances (
 run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, phase TEXT NOT NULL,
 item_id TEXT NOT NULL, revision TEXT NOT NULL, publications INTEGER NOT NULL DEFAULT 0,
 errors TEXT NOT NULL DEFAULT '{}', last_error TEXT, consecutive INTEGER NOT NULL DEFAULT 0,
 exhausted TEXT, PRIMARY KEY(run_id,item_id,revision)
);
"""


def error_subjects(error, payload, items):
    """Use typed locations/subject paths, never changing UUIDs or prose as a key."""
    by_id = {i["item_id"]: i for i in items}
    found = []
    if isinstance(error, ValidationError):
        decisions = payload.get("review_decisions", []) if isinstance(payload, dict) else []
        for detail in error.errors():
            loc = detail["loc"]
            subject = None
            if len(loc) > 1 and loc[0] == "review_decisions" and isinstance(loc[1], int):
                index = loc[1]
                value = decisions[index] if index < len(decisions) else {}
                subject = value.get("item_id") if isinstance(value, dict) else None
                if subject is None and index < len(items):
                    subject = items[index]["item_id"]
            elif len(loc) > 1 and loc[0] == "verification_reviews" and isinstance(loc[1], int):
                reviews = payload.get("verification_reviews", []) if isinstance(payload, dict) else []
                value = reviews[loc[1]] if loc[1] < len(reviews) else {}
                if isinstance(value, dict):
                    subject = next((i["item_id"] for i in items if i.get("finding_id") == value.get("finding_id")), None)
            field = ".".join(str(p) for p in loc if not isinstance(p, int))
            found.append((subject if subject in by_id else None, f"schema:{field}:{detail['type']}"))
    else:
        text = str(error)
        paths = re.findall(r"review_decisions\[([^\]]+)\]\.([a-z_]+)", text)
        for subject, field in paths:
            if subject in by_id:
                found.append((subject, "contract:" + field))
        if not found:
            category = getattr(error, "category", None)
            if category is None:
                category = next((name for name in (
                    "verification_reviews", "comparison_assessments", "distinct_from", "duplicate_of",
                    "review_batch_id", "review_decisions", "focus", "risk_outcome", "revision") if name in text), "semantic")
            found.append((None, str(category)))
    return {(item["item_id"], category) for subject, category in found for item in items
            if subject is None or item["item_id"] == subject}


class ReviewControlMixin:
    def review_allowances(self, run_id, phase):
        return {(r["item_id"], r["revision"]): {**dict(r), "errors": json.loads(r["errors"])}
                for r in self._rows("SELECT * FROM audit_review_allowances WHERE run_id=?", (run_id,))}

    def _allowance_batch(self, run_id, batch_id):
        self.assert_execution_write(run_id)
        batch = self.active_review_batch(run_id, batch_id=batch_id)
        run = self._row("SELECT status FROM runs WHERE id=?", (run_id,))
        if not run or run[0] != "running" or not batch or batch["id"] != batch_id or not self.execution_write_allowed(run_id, batch["epoch"]):
            raise StopAudit("cancelled", "审查租约已失效，不再消耗或修改此项额度。")
        return batch

    def reserve_review_publication(self, run_id, batch_id):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                batch = self._allowance_batch(run_id, batch_id)
                ledger = self.review_allowances(run_id, batch["phase"])
                if any(ledger.get((i["item_id"], i["revision"]), {}).get("exhausted") or
                       ledger.get((i["item_id"], i["revision"]), {}).get("publications", 0) >= 3 for i in batch["items"]):
                    raise StopAudit("review_item_exhausted", "当前对象版本已达到累计纠错上限，宿主将延后该项。")
                for item in batch["items"]:
                    self._db.execute("INSERT INTO audit_review_allowances(run_id,phase,item_id,revision,publications)"
                                     " VALUES(?,?,?,?,1) ON CONFLICT(run_id,item_id,revision) DO UPDATE"
                                     " SET publications=publications+1",
                                     (run_id, batch["phase"], item["item_id"], item["revision"]))
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise
    def check_review_publication(self, run_id, batch_id):
        with self._lock:
            batch = self._allowance_batch(run_id, batch_id)
            ledger = self.review_allowances(run_id, batch["phase"])
            if any(ledger.get((i["item_id"], i["revision"]), {}).get("exhausted") or
                   ledger.get((i["item_id"], i["revision"]), {}).get("publications", 0) >= 3 for i in batch["items"]):
                raise StopAudit("review_item_exhausted", "当前对象版本已达到累计纠错上限，宿主将延后该项。")

    def reject_review_publication(self, run_id, batch_id, error, payload=None):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                batch = self._allowance_batch(run_id, batch_id)
                ledger = self.review_allowances(run_id, batch["phase"])
                subjects = error_subjects(error, payload, batch["items"])
                for item in batch["items"]:
                    categories = sorted(c for ident, c in subjects if ident == item["item_id"])
                    if not categories:
                        continue
                    row = ledger.get((item["item_id"], item["revision"]))
                    if not row:
                        continue  # Only admitted semantic requests own a publication.
                    errors = row["errors"]
                    for category in categories:
                        errors[category] = errors.get(category, 0) + 1
                    # One response with many errors is one correction, not many retries.
                    repeated = set((row["last_error"] or "").split("|")) & set(categories)
                    consecutive = row["consecutive"] + 1 if repeated else 1
                    exhausted = ("repeated_error:" + sorted(repeated)[0] if repeated and consecutive >= 2 else
                                 "publication_limit" if row["publications"] >= 3 else None)
                    self._db.execute("UPDATE audit_review_allowances SET errors=?,last_error=?,consecutive=?,exhausted=?"
                                     " WHERE run_id=? AND item_id=? AND revision=?",
                                     (json.dumps(errors, sort_keys=True), "|".join(categories), consecutive, exhausted,
                                      run_id, item["item_id"], item["revision"]))
                    self.append_event(run_id, None, "review_item_correction", {
                        "batch_id": batch_id, "phase": batch["phase"], "item_id": item["item_id"],
                        "revision": item["revision"], "publications": row["publications"],
                        "error_types": categories, "consecutive": consecutive, "exhausted": exhausted})
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise
        if (batch['phase'] == 'final' and len(batch['items']) > 1
                and all(item['kind'] == 'risk' for item in batch['items'])):
            from .submission import reference_coordinates
            if not any(reference_coordinates(item)['peers'] for item in batch['items']):
                self.defer_review_batch(run_id, batch_id,
                    '首次拒收后隔离独立风险，避免正常项陪同消耗纠错额度；保留逐项累计账本。', split=True)
                raise StopAudit('review_batch_split', '独立风险批次已隔离，保留累计额度，按当前项继续判读。')
