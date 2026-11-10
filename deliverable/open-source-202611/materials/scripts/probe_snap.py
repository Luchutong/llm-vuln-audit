import json

p = r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\snapshot_full.json"
d = json.load(open(p, encoding="utf-8"))
out = []
out.append("top keys: " + ", ".join(d.keys()))
files = d.get("files", [])
units = d.get("units", [])
out.append("files n=%d units n=%d" % (len(files), len(units)))
out.append("--- one file ---")
out.append(json.dumps(files[0], ensure_ascii=False, indent=1)[:1500])
out.append("--- one unit ---")
out.append(json.dumps(units[0], ensure_ascii=False, indent=1)[:2000])
open(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\snap_probe.txt", "w", encoding="utf-8").write("\n".join(out))
print("done")
