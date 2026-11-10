#!/usr/bin/env python3
import json, sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

print("TOP-LEVEL KEYS:", list(data.keys()))
print()
for k, v in data.items():
    if isinstance(v, (str, int, float, bool)) or v is None:
        print(f"{k} = {v}")
    elif isinstance(v, list):
        print(f"{k}: list len={len(v)}")
    elif isinstance(v, dict):
        print(f"{k}: dict keys={list(v.keys())[:30]}")
