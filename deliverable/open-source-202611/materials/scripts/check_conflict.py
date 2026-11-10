import json
from pathlib import Path

DATA = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import")
snap = json.loads((DATA / "snapshot_full.json").read_text(encoding="utf-8"))
by_file = {}
for u in snap["units"]:
    by_file.setdefault(u["file_path"], []).append(u)

shown = 0
prefix_ok = 0
substr_ok = 0
other = 0
for path, us in by_file.items():
    seen = {}
    cols = {}
    for u in us:
        for cl in u["cleaned_lines"]:
            n = cl["number"]
            if n in seen and seen[n] != cl["text"]:
                a, b = seen[n], cl["text"]
                if a.startswith(b) or b.startswith(a):
                    prefix_ok += 1
                elif a in b or b in a:
                    substr_ok += 1
                else:
                    other += 1
                    if shown < 8:
                        shown += 1
                        print("PATH", path, "line", n)
                        print("  A=[%s]" % a)
                        print("  B=[%s]" % b)
                # keep the longer one
                if len(b) > len(a):
                    seen[n] = b
            else:
                seen[n] = cl["text"]
print("prefix_relation=%d substring=%d other=%d" % (prefix_ok, substr_ok, other))
