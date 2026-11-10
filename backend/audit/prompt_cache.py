"""Provider-reported prompt cache usage, never inferred from repeated text.

OpenAI-compatible totals include cache reads; native Anthropic input excludes reads
and writes. Keep that distinction at the boundary and aggregate tokens, not averaged
percentages. Missing/invalid counters stay unknown, including explicit zero hits.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _get(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else getattr(value, key, None)


def _count(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _first(*values: Any) -> int | None:
    return next((n for v in values if (n := _count(v)) is not None), None)


def normalize_usage(raw: Any, *, input_tokens: int | None = None,
                    anthropic: bool = False) -> dict:
    """Small safe projection of usage only; never expose response text/credentials."""
    read = write = total = None
    source = "unreported"
    if anthropic:
        read = _first(_get(raw, "cache_read_input_tokens"), _get(raw, "cache_read_tokens"))
        write = _first(_get(raw, "cache_creation_input_tokens"), _get(raw, "cache_write_tokens"))
        miss = _count(_get(raw, "input_tokens"))
        # All components must be present to avoid publishing a false denominator.
        if miss is not None and read is not None and write is not None:
            total = miss + read + write
        source = "anthropic" if read is not None else source
    else:
        total = _first(_get(raw, "prompt_tokens"), _get(raw, "input_tokens"), input_tokens)
        read = _count(_get(raw, "prompt_cache_hit_tokens"))
        if read is not None:
            source = "deepseek"
            miss = _count(_get(raw, "prompt_cache_miss_tokens"))
            if total is None and miss is not None:
                total = read + miss
            elif miss is not None and total is not None and read + miss != total:
                read, source = None, "invalid"
        else:
            read = _first(_get(_get(raw, "prompt_tokens_details"), "cached_tokens"),
                          _get(_get(raw, "input_tokens_details"), "cached_tokens"))
            if read is not None:
                source = "compatible"
        write = _count(_get(raw, "cache_creation_input_tokens"))
    if read is not None and total is not None and read > total:
        read, source = None, "invalid"
    return {"input_tokens": total, "cache_read_tokens": read, "cache_write_tokens": write,
            "source": source}


def message_cache_usage(message: Any) -> dict:
    usage = _get(_get(message, "raw"), "usage")
    return normalize_usage(usage, input_tokens=_get(_get(message, "token_usage"), "input_tokens"))


@dataclass
class CacheTotals:
    usage_records: int = 0
    reported_records: int = 0
    hit_records: int = 0
    known_input_tokens: int = 0
    reported_input_tokens: int = 0
    known_cache_read_tokens: int = 0
    known_cache_write_tokens: int = 0
    write_reported_records: int = 0

    def add(self, usage: dict) -> None:
        self.usage_records += 1
        total = _count(usage.get("input_tokens"))
        read = _count(usage.get("cache_read_tokens"))
        write = _count(usage.get("cache_write_tokens"))
        self.known_input_tokens += total or 0
        if read is not None and total is not None and read <= total:
            self.reported_records += 1
            self.hit_records += int(read > 0)
            self.reported_input_tokens += total
            self.known_cache_read_tokens += read
        if write is not None:
            self.write_reported_records += 1
            self.known_cache_write_tokens += write

    def view(self) -> dict:
        from dataclasses import asdict
        return {**asdict(self),
                "cache_read_tokens": self.known_cache_read_tokens if self.reported_records else None,
                "cache_write_tokens": self.known_cache_write_tokens if self.write_reported_records else None,
                "cache_hit_ratio": (self.known_cache_read_tokens / self.reported_input_tokens
                                    if self.reported_input_tokens else None),
                "record_coverage": self.reported_records / self.usage_records if self.usage_records else None,
                "complete": bool(self.usage_records and self.reported_records == self.usage_records)}


@dataclass
class PromptCacheStats:
    total: CacheTotals = field(default_factory=CacheTotals)
    by_role: dict[str, CacheTotals] = field(default_factory=dict)

    def add(self, usage: dict, role: str = "unknown") -> None:
        self.total.add(usage)
        self.by_role.setdefault(role, CacheTotals()).add(usage)

    def view(self) -> dict:
        return {"version": "prompt-cache-v1", **self.total.view(),
                "by_role": {k: v.view() for k, v in sorted(self.by_role.items())}}

    @classmethod
    def restore(cls, value: dict) -> "PromptCacheStats":
        def totals(data):
            return CacheTotals(**{k: _count(data.get(k)) or 0 for k in CacheTotals.__dataclass_fields__})
        return cls(totals(value), {k: totals(v) for k, v in value.get("by_role", {}).items()})

    def consume(self, kind: str, payload: dict) -> None:
        if kind == "model_response":
            phase = str(payload.get("phase") or "unknown")
            role = ("history_summary" if payload.get("purpose") == "history_summary" else
                    str(payload["cache_role"]) if payload.get("cache_role") else
                    "reviewer" if payload.get("review_phase") or phase.startswith("planner_review") else
                    "worker" if phase.startswith("task_") else phase.partition("_")[0])
            usage = payload.get("prompt_cache")
            if not isinstance(usage, dict):
                usage = normalize_usage({}, input_tokens=payload.get("input_tokens"))
            self.add(usage, role)
        elif kind == "poc_runtime_usage":
            usage = payload.get("usage") or {}
            normalized = usage.get("prompt_cache") or normalize_usage(usage, anthropic=True)
            self.add(normalized, "poc_sdk")


class PromptCacheStoreMixin:
    """Persist an append-aware projection; polling never replays the full event log."""

    def _init_prompt_cache(self):
        self._db.execute("CREATE TABLE IF NOT EXISTS run_prompt_cache ("
                         "run_id TEXT PRIMARY KEY, last_event_id INTEGER NOT NULL, stats TEXT NOT NULL)")

    def prompt_cache_usage(self, run_id: str) -> dict:
        import json
        with self._lock:
            readonly = getattr(self, "_readonly", False)
            memory = getattr(self, "_prompt_cache_memory", {})
            cached = memory.get(run_id) if readonly else None
            if cached is not None:
                after, saved = cached
                stats = PromptCacheStats.restore(saved)
            else:
                # Archived databases can predate this projection table. A read-only
                # inspector must neither migrate the archive nor write a cursor to it.
                present = (not readonly or self._db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='run_prompt_cache'").fetchone())
                row = self._db.execute("SELECT * FROM run_prompt_cache WHERE run_id=?", (run_id,)).fetchone() if present else None
                after = row["last_event_id"] if row else 0
                stats = PromptCacheStats.restore(json.loads(row["stats"])) if row else PromptCacheStats()
            latest = self._db.execute("SELECT MAX(id) FROM events WHERE run_id=?", (run_id,)).fetchone()[0] or 0
            if latest > after:
                for event in self._db.execute(
                        "SELECT kind,payload FROM events WHERE run_id=? AND id>? AND id<=? "
                        "AND kind IN ('model_response','poc_runtime_usage') ORDER BY id", (run_id, after, latest)):
                    payload = json.loads(event["payload"])
                    if isinstance(payload, dict):
                        stats.consume(event["kind"], payload)
                if readonly:
                    memory[run_id] = (latest, stats.view())
                else:
                    self._db.execute("INSERT INTO run_prompt_cache(run_id,last_event_id,stats) VALUES(?,?,?) "
                                     "ON CONFLICT(run_id) DO UPDATE SET last_event_id=excluded.last_event_id,stats=excluded.stats",
                                     (run_id, latest, json.dumps(stats.view(), separators=(",", ":"))))
            return stats.view()


def cache_markdown(stats: dict | None) -> list[str]:
    """Shared live/legacy/frozen-report wording, with an explicit partial denominator."""
    if not stats:
        return []
    n, reported = stats.get("usage_records", 0), stats.get("reported_records", 0)
    ratio = stats.get("cache_hit_ratio")
    label = f"{ratio:.2%}" if isinstance(ratio, (int, float)) else "暂无数据"
    tokens = stats.get("cache_read_tokens")
    writes = stats.get("cache_write_tokens")
    return ["### API 提示缓存", "",
            f"- 输入 token 命中率：{label}；命中 {tokens if tokens is not None else '未报告'} tokens / "
            f"已报告缓存的输入 {stats.get('reported_input_tokens', 0)} tokens。",
            f"- 数据覆盖：{reported}/{n} 条用量记录；缓存写入 {writes if writes is not None else '未报告'} tokens。",
            "- 命中率按供应商返回的 token 加权；未报告不按零命中处理。SDK 每阶段汇总记一条，其余每次响应记一条。"
            "提示缓存仍消耗模型请求额度；本项不包含工具缓存，也不估算未配置的费用。", ""]
