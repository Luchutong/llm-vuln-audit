"""Passive circuit breaker for the configured model.

Mirrors the ARTEX llmpool health design: there is no background prober. State only
moves when a real request succeeds or fails, and a cooled-down model is probed by
the next real request. Cooldown grows 1 -> 5 -> 30 minutes across consecutive trips.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

COOLDOWN_LADDER = (60, 300, 1800)
SOFT_TRIP_AFTER = 3
HARD_STATUS = {401, 402, 403, 404, 408, 429}


@dataclass
class BreakerState:
    fails: int = 0
    trips: int = 0
    open_until: float = 0.0
    last_error: str = ""
    last_at: float = 0.0

    def open(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) < self.open_until

    def snapshot(self, now: float | None = None) -> dict:
        moment = now if now is not None else time.time()
        if self.open(moment):
            status = "tripped"
        elif self.fails:
            status = "degraded"
        else:
            status = "ok"
        return {
            "status": status,
            "fails": self.fails,
            "trips": self.trips,
            "cooldown_seconds": max(0, int(self.open_until - moment)),
            "last_error": self.last_error,
            "last_at": self.last_at,
        }


@dataclass
class ModelHealth:
    """Breaker keyed by model name; persisted by the caller through ``on_change``."""

    state: BreakerState = field(default_factory=BreakerState)
    on_change: object | None = None

    def reset(self) -> None:
        self.state = BreakerState()
        self._persist()

    def is_open(self) -> bool:
        return self.state.open()

    def pass_(self) -> None:
        if self.state.fails or self.state.trips or self.state.open_until:
            self.state = BreakerState(last_at=time.time())
            self._persist()

    def trip(self, message: str, *, status: int | None = None) -> None:
        state = self.state
        state.fails += 1
        state.last_error = message[:400]
        state.last_at = time.time()
        hard = status in HARD_STATUS
        if hard or state.fails >= SOFT_TRIP_AFTER:
            state.trips += 1
            index = min(state.trips, len(COOLDOWN_LADDER)) - 1
            state.open_until = state.last_at + COOLDOWN_LADDER[index]
            state.fails = 0
        self._persist()

    def snapshot(self) -> dict:
        return self.state.snapshot()

    def restore(self, row: dict | None) -> None:
        if not row:
            return
        state = BreakerState(
            fails=int(row.get("fails") or 0),
            trips=int(row.get("trips") or 0),
            open_until=float(row.get("open_until") or 0.0),
            last_error=str(row.get("last_error") or ""),
            last_at=float(row.get("last_at") or 0.0),
        )
        # An expired window is dropped on restore, matching ARTEX's LoadLLMHealth.
        if state.open_until and not state.open():
            state.open_until = 0.0
        self.state = state

    def _persist(self) -> None:
        if self.on_change is not None:
            self.on_change(self.state)
