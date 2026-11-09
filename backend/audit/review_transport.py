"""Host-owned exact-version pagination; no executable model reading loops."""
from __future__ import annotations

import json
import math
import time
from copy import deepcopy

from .review_input import access_complete, digest, field_values, same_input, source_input
from .runtime import StopAudit

PAGE_CHARACTERS = 4096


def merge_ranges(ranges):
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return merged


def unread_ranges(ranges, length):
    cursor = 0
    for start, end in merge_ranges(ranges):
        if cursor < start:
            yield cursor, min(start, length)
        cursor = max(cursor, end)
    if cursor < length:
        yield cursor, length


def reading_work(items):
    pages = characters = 0
    for item in items:
        for part in item.get("paged_fields", []):
            for start, end in unread_ranges((item.get("read_ranges") or {}).get(part["field"], []), part["characters"]):
                pages += math.ceil((end - start) / PAGE_CHARACTERS)
                characters += end - start
    return {"pages": pages, "characters": characters, "page_characters": PAGE_CHARACTERS}


class ReviewTransportMixin:
    def restore_review_cursors(self, run_id, phase, items):
        """Copy receipts into a new lease only for the exact field bytes and version.

        The old lease ID/epoch stays fenced, including callbacks from a paused owner.
        Receipts are host reads, never a model's claim of having read something.
        """
        for batch in reversed(self.list_review_batches(run_id)):
            if batch["phase"] != phase:
                continue
            old = {(i["item_id"], i["revision"]): i for i in batch["items"]}
            for item in items:
                previous = old.get((item["item_id"], item["revision"]))
                if not previous:
                    continue
                manifests = {p["field"]: p for p in previous.get("paged_fields", [])}
                for part in item.get("paged_fields", []):
                    before = manifests.get(part["field"], {})
                    if (before.get("sha256"), before.get("characters")) != (part["sha256"], part["characters"]):
                        continue
                    ranges = item.setdefault("read_ranges", {}).setdefault(part["field"], [])
                    ranges.extend((previous.get("read_ranges") or {}).get(part["field"], []))
                    item["read_ranges"][part["field"]] = merge_ranges(ranges)
                if item.get("paged_fields"):
                    item["review_input_omitted"] = not access_complete(item)
        return items

    def materialize_review_batch(self, run_id, batch_id, *, repository=None, max_bytes=262144, deadline=None):
        """Assemble typed facts before permitting any semantic publication.

        Original fields are reconstructed once, rather than on every 1 KiB tool call.
        Unread intervals are persisted one page at a time; resume/split preserves them.
        The complete assembled facts are handed to the model in its bounded request,
        including previously read pages. No summary replaces source or POC evidence.
        """
        from .review_store import dump, stamp
        with self._lock:
            batch = self._allowance_batch(run_id, batch_id)
            if len(batch["items"]) > 16:
                raise StopAudit("review_input_too_large", "关联候选超过单批判读上限，保留整个关联组待审。")
            candidates = self._review_candidates(run_id, batch["phase"])
            current = {i["item_id"]: i for i in candidates}
            if any(not same_input(i, current.get(i["item_id"])) for i in batch["items"]):
                raise ValueError("批次版本已变化，不能继续读取旧分页")
            needs_related = any(p["field"] == "payload.related_claims" for i in batch["items"] for p in i.get("paged_fields", []))
            enriched = self._review_source_inputs(candidates, repository) if needs_related else {}
            assembled = []
            for item in batch["items"]:
                full = current[item["item_id"]]
                if batch["phase"] == "final" and full["kind"] in {"finding", "risk"}:
                    full = enriched.get(item["item_id"]) or source_input(full, repository)
                value = deepcopy(item)
                for part in item.get("paged_fields", []):
                    text = dump(field_values(full)[part["field"]])
                    if digest(text) != part["sha256"] or len(text) != part["characters"]:
                        self._db.execute("UPDATE audit_review_batches SET status='stale',finished_at=? WHERE id=?", (stamp(), batch_id))
                        raise StopAudit("review_input_changed", "分页字段原文已变化，旧租约失效；保留额度并重新领取当前事实。")
                    decoded = json.loads(text)
                    if part["field"].startswith("payload."):
                        value["payload"][part["field"].removeprefix("payload.")] = decoded
                    else:
                        value[part["field"]] = decoded
                assembled.append(value)
            # Fail closed before marking anything delivered when exact facts cannot fit.
            size = len(dump(assembled).encode())
            if size > max_bytes:
                raise StopAudit("review_input_too_large", f"本批完整事实 {size} 字节超过审查输入窗口 {max_bytes}；保留待审。")
            work = reading_work(batch["items"])
            for item in batch["items"]:
                for part in item.get("paged_fields", []):
                    field = part["field"]
                    ranges = item.setdefault("read_ranges", {}).setdefault(field, [])
                    for start, end in list(unread_ranges(ranges, part["characters"])):
                        for offset in range(start, end, PAGE_CHARACTERS):
                            if deadline is not None and time.monotonic() >= deadline:
                                raise StopAudit("timeout", "宿主分页尚未读完，保留游标，禁止进入判决发布。")
                            self.assert_execution_write(run_id)
                            ranges[:] = merge_ranges([*ranges, [offset, min(end, offset + PAGE_CHARACTERS)]])
                            self._db.execute("UPDATE audit_review_batches SET items=? WHERE id=?", (dump(batch["items"]), batch_id))
                item["review_input_omitted"] = not access_complete(item)
            self._db.execute("UPDATE audit_review_batches SET items=? WHERE id=?", (dump(batch["items"]), batch_id))
            if not all(access_complete(i) for i in batch["items"]):
                raise StopAudit("review_read_incomplete", "分页尚未完整传送，不能发布接受或动态确认。")
            for value in assembled:
                value["review_input_omitted"] = False
                value.pop("read_ranges", None)
            self.append_event(run_id, None, "review_input_prepared", {
                "batch_id": batch_id, "phase": batch["phase"], "items": len(assembled),
                "input_bytes": size, "reading_work": work, "reader": "host-exact-fields-v1"})
            return {**batch, "items": assembled}
