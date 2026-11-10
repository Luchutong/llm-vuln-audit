#!/usr/bin/env python3
import json, sys

for path in sys.argv[1:]:
    print("=" * 70)
    print("FILE:", path.split("\\")[-1])
    print("=" * 70)
    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    print("id           =", d["id"])
    print("name         =", d["name"])
    print("created_at   =", d["created_at"])
    print("archive_sha  =", d["archive_sha256"])
    print("profile      =", d["target_profile"])
    print("files (raw)  =", len(d["files"]))
    print("units        =", len(d["units"]))
    print("warnings     =", len(d["warnings"]))
    print("excluded     =", len(d["excluded_files"]))
    print("skipped      =", len(d["skipped_files"]))
    print("--- stats ---")
    for k, v in d["stats"].items():
        if k == "languages":
            print("languages:")
            for lang, cnt in sorted(v.items(), key=lambda x: -x[1]):
                print(f"  {lang:12s} {cnt}")
        else:
            print(f"{k:22s} = {v}")
    print()
