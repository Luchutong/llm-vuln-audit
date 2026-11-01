"""Bounded exploration extensions paid from the existing execution budget."""
from __future__ import annotations


class EvidenceYield:
    def __init__(self, ledger, *, ceiling, emit):
        self.ledger, self.ceiling, self.emit = ledger, ceiling, emit
        self.seen = set(ledger.lines)

    def extend(self, current):
        now = set(self.ledger.lines)
        new = now - self.seen
        before_paths = {key[0] for key in self.seen}
        new_paths = {key[0] for key in new} - before_paths
        # A new dependency plus concrete lines, or a substantial new source window.
        # Logs, retries and repeated reads never qualify. No counters are reset.
        if current >= self.ceiling or not (len(new) >= 80 or (new_paths and len(new) >= 20)):
            return current
        limit = min(self.ceiling, current + 2)
        self.seen = now
        self.emit({"kind": "worker_exploration_extended", "policy": "evidence-yield-v1", "previous_limit": current,
                   "response_limit": limit, "ceiling": self.ceiling, "new_source_lines": len(new),
                   "new_paths": sorted(new_paths), "reason": "实际新增源码证据；继续共享原单次及整次预算"})
        return limit
