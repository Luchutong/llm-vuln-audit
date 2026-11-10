import json
from pathlib import Path

DATA = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import")
out = []

# phpMyFAQ: why 9221 is_php but 9211 processed
snap = json.loads((DATA / "snapshot_full.json").read_text(encoding="utf-8"))
php = [f for f in snap["files"] if f["is_php"]]
excluded_php = [f for f in php if f.get("excluded")]
out.append("is_php=%d excluded_among_php=%d" % (len(php), len(excluded_php)))
for f in excluded_php:
    out.append("  EXC: %s | %s" % (f["path"], f.get("exclude_reason")))

# check cleaned-line text consistency across overlapping slices
by_file = {}
for u in snap["units"]:
    by_file.setdefault(u["file_path"], []).append(u)
conflicts = 0
multi = 0
for path, us in by_file.items():
    seen = {}
    for u in us:
        for cl in u["cleaned_lines"]:
            if cl["number"] in seen and seen[cl["number"]] != cl["text"]:
                conflicts += 1
            seen[cl["number"]] = cl["text"]
    if len(us) > 1:
        multi += 1
out.append("files_with_multiple_units=%d cleaned_text_conflicts=%d" % (multi, conflicts))

# verify line_count vs my orig line formula on a sample
import zipfile
zf = zipfile.ZipFile(DATA / "phpmyfaq-4.1.1-audit.zip")
mismatch = 0
checked = 0
for f in php[:2000]:
    raw = zf.read(f["path"])
    calc = raw.count(b"\n") + (0 if raw.endswith(b"\n") or not raw else 1)
    checked += 1
    if calc != f["line_count"]:
        mismatch += 1
        if mismatch <= 5:
            out.append("  LINEMISMATCH %s calc=%d record=%d" % (f["path"], calc, f["line_count"]))
out.append("line_count checked=%d mismatch=%d" % (checked, mismatch))

# Lab30: confirm no non-security comments really (comment=0)
s30 = json.loads((DATA / "snapshot_lab30.json").read_text(encoding="utf-8"))
reasons = {}
for u in s30["units"]:
    for o in u["omissions"]:
        reasons[o["reason"]] = reasons.get(o["reason"], 0) + 1
out.append("lab30 omission reasons (with overlap, raw): %s" % json.dumps(reasons, ensure_ascii=False))

# how many phpMyFAQ units carry overlap > 0
ov = sum(1 for u in snap["units"] if u["slice_rule"].get("overlap_lines", 0) > 0)
out.append("phpmyfaq units with overlap>0 = %d" % ov)

(DATA / "verify_dc03.txt").write_text("\n".join(out), encoding="utf-8")
print("done")
