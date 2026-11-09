import json
d = json.load(open("/tmp/cloc_20261108.json", encoding="utf-8"))
tot = {k: v for k, v in d.items() if isinstance(v, dict) and "nFiles" in v}
print("LANG".ljust(24), "FILES", "BLANK", "COMMENT", "CODE")
for k, v in sorted(tot.items(), key=lambda x: -x[1]["code"]):
    print(f'{k:<24}{v["nFiles"]:>6}{v["blank"]:>8}{v["comment"]:>9}{v["code"]:>9}')
s = d.get("SUM") or {}
print("SUM", json.dumps(s))
