import json
from pathlib import Path

DATA = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import")
snap = json.loads((DATA / "snapshot_full.json").read_text(encoding="utf-8"))
zero = [u for u in snap["units"] if len(u["cleaned_lines"]) == 0]
out = ["zero_line_slices=%d" % len(zero)]
for u in zero[:10]:
    out.append("  %s %s bytes=%d->%d rule=%s" %
               (u["file_path"].split("/")[-1], u["symbol"],
                u["start_byte"], u["end_byte"], u["slice_rule"]["boundary"]))
# also count empty by byte range
zero_byte = [u for u in snap["units"] if u["end_byte"] - u["start_byte"] == 0]
out.append("zero_byte_range_slices=%d" % len(zero_byte))
# how many slices hit the 200-line cap
cap = [u for u in snap["units"] if len(u["cleaned_lines"]) == 200]
out.append("slices_at_200_lines=%d" % len(cap))
# how many hit 16KB cap
capb = [u for u in snap["units"] if u["end_byte"] - u["start_byte"] >= 16384]
out.append("slices_at_16KB=%d" % len(capb))
(DATA / "zero_check.txt").write_text("\n".join(out), encoding="utf-8")
print("done")
