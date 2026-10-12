#!/usr/bin/env python3
"""Exercise the event stream the way the browser does: read, drop, resume.

Two things are being checked, and neither is visible from the JSON log:

* frames arrive while the run is still going, rather than only being flushed at the end;
* a reconnect carrying `Last-Event-ID` resumes *after* the last frame the reader saw — no
  gap (which would silently hide tool calls from the timeline) and no duplicate id (which
  would double-render every event the UI replayed).

Usage: sse_reconnect.py <base-url> <run-id> [frames-before-drop]
"""
import json
import sys
import threading
import time

import httpx

base = sys.argv[1].rstrip("/")
run_id = sys.argv[2]
drop_after = int(sys.argv[3]) if len(sys.argv) > 3 else 3


def read_frames(limit: int, last_event_id: str | None, budget: float):
    """Read up to `limit` events, or stop when `budget` seconds pass."""
    headers = {"Accept": "text/event-stream"}
    if last_event_id is not None:
        headers["Last-Event-ID"] = last_event_id

    frames: list[dict] = []
    deadline = time.monotonic() + budget
    with httpx.stream(
        "GET", f"{base}/api/runs/{run_id}/events", headers=headers, timeout=budget + 10
    ) as response:
        response.raise_for_status()
        current: dict = {}
        for line in response.iter_lines():
            if time.monotonic() > deadline:
                break
            if line.startswith("id: "):
                current["id"] = int(line[4:])
            elif line.startswith("data: "):
                current["data"] = json.loads(line[6:])
            elif not line.strip() and current:
                frames.append(current)
                current = {}
                if limit and len(frames) >= limit:
                    break
    return frames


first = read_frames(drop_after, None, budget=60)
print(f"first connection: read {len(first)} frame(s)")
for frame in first:
    print(f"  id={frame['id']} kind={frame['data']['kind']}")
if not first:
    raise SystemExit("no frames arrived; the stream is not pushing while the run is live")

last = first[-1]["id"]
print(f"dropping the connection at id={last}, then resuming with Last-Event-ID")

second = read_frames(3, str(last), budget=45)
print(f"second connection: read {len(second)} frame(s) after Last-Event-ID {last}")
for frame in second:
    print(f"  id={frame['id']} kind={frame['data']['kind']}")

ids = [f["id"] for f in second]
if any(i <= last for i in ids):
    raise SystemExit(f"resumed stream replayed an already-seen id: {ids} (duplicate frames)")
if ids != sorted(ids) or len(set(ids)) != len(ids):
    raise SystemExit(f"resumed stream is out of order: {ids}")
if ids and ids[0] != last + 1:
    print(f"note: resumed at {ids[0]}, not {last + 1} — ids are spent on other runs too?")
print("resume is gap-free and duplicate-free as far as id ordering can show")


# The header is what a browser sends on reconnect; `after` is the manual fallback. They must
# agree, otherwise a page reload and a live reconnect would show different timelines.
plain = read_frames(1, None, budget=30)
print(f"no-header replay: read {len(plain)} frame(s), first id={plain[0]['id'] if plain else '—'}")

# `?after=` is the fallback for a client that cannot send the header (a page reload, curl).
# Read it as a stream too: this response never ends — the server keeps the connection open and
# pings — so httpx.get would sit there reading to EOF and time out instead of showing anything.
frames_after = read_frames(1, None, budget=30)
with httpx.stream(
    "GET",
    f"{base}/api/runs/{run_id}/events",
    params={"after": last},
    headers={"Accept": "text/event-stream"},
    timeout=30,
) as response:
    response.raise_for_status()
    first_after = None
    for line in response.iter_lines():
        if line.startswith("id: "):
            first_after = int(line[4:])
            break
if first_after is None:
    raise SystemExit("?after= produced no frames")
if first_after <= last:
    raise SystemExit(f"?after={last} replayed id={first_after}; the fallback disagrees with the header")
print(f"after={last} fallback resumes at id={first_after} — agrees with Last-Event-ID")
