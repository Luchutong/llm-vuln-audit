import json

p = r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\snapshot_full.json"
d = json.load(open(p, encoding="utf-8"))
u = d["units"][0]
out = ["unit keys: " + ", ".join(u.keys())]
for k in ("omissions", "slice_rule", "index", "security_comments"):
    if k in u:
        out.append("--- %s ---" % k)
        out.append(json.dumps(u[k], ensure_ascii=False)[:1200])
# find a unit that has omissions
for x in d["units"]:
    if x.get("omissions"):
        out.append("--- unit with omissions: %s ---" % x["file_path"])
        out.append(json.dumps(x["omissions"], ensure_ascii=False)[:1500])
        break
open(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\unit_probe.txt", "w", encoding="utf-8").write("\n".join(out))
print("done")
