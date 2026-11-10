#!/usr/bin/env python3
import json
from pathlib import Path
from PIL import Image

root = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\deliverable\open-source-202611")
print("=== image integrity ===")
imgs = sorted(root.rglob("*.png"))
for p in imgs:
    with Image.open(p) as im:
        im.verify()
    with Image.open(p) as im:
        w, h = im.size
    print(f"OK  {p.name:48s} {w}x{h}  {p.stat().st_size:>9d} B")
print(f"total images: {len(imgs)}")

print("\n=== JSON validity ===")
for p in sorted(root.rglob("*.json")):
    data = json.loads(p.read_text(encoding="utf-8"))
    if p.name == "D-C02_真值集.json":
        print(f"OK  {p.name}  top keys: {list(data.keys())}")
    else:
        print(f"OK  {p.name}  {len(str(data))} chars")

print("\n=== markdown docs ===")
for p in sorted(root.rglob("*.md")):
    print(f"OK  {p.name:32s} {p.stat().st_size:>8d} B")
