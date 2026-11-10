import json
import sys
import zipfile
from pathlib import Path

import tiktoken

REPO = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
sys.path.insert(0, str(REPO / "backend"))
from audit.source import SourceRepository, _offsets, _walk, _decode, SECURITY_COMMENT, STRING_TYPES

DATA = REPO / "data" / "part-c-import"
enc = tiktoken.get_encoding("cl100k_base")
repo = SourceRepository(Path(r"C:\pmf_audit"))
out = []

# ---- verify omissions multi-record accounting on phpMyFAQ whole files ----
snap = json.loads((DATA / "snapshot_full.json").read_text(encoding="utf-8"))
zf = zipfile.ZipFile(DATA / "phpmyfaq-4.1.1-audit.zip")
processed = [f for f in snap["files"] if f["is_php"] and not f.get("excluded")]

multi_record_lines = 0
double_marked = 0
sample_double = []
for f in processed[:1500]:
    content = zf.read(f["path"])
    with repo._parser_lock:
        tree = repo.parser.parse(content)
    nodes = list(_walk(tree.root_node))
    comments = [(n.start_byte, n.end_byte,
                 bool(SECURITY_COMMENT.search(_decode(content[n.start_byte:n.end_byte]))))
                for n in nodes if n.type == "comment"]
    protected = [(n.start_byte, n.end_byte) for n in nodes if n.type in STRING_TYPES]
    offsets = _offsets(content)
    rows, omissions = repo._clean(content, 0, len(content), offsets, comments, protected)
    # count lines that have >1 omission record
    from collections import Counter
    c = Counter(o["start_line"] for o in omissions)
    multi_record_lines += sum(1 for ln, k in c.items() if k > 1)
    # lines marked both comment and blank
    rk = {}
    for o in omissions:
        rk.setdefault(o["start_line"], set()).add(o["reason"])
    dm = [ln for ln, rs in rk.items() if len(rs) > 1]
    double_marked += len(dm)
    if dm and len(sample_double) < 5:
        for ln in dm[:2]:
            sample_double.append("%s line %d" % (f["path"], ln))

out.append("first 1500 files: lines with >1 omission record=%d" % multi_record_lines)
out.append("first 1500 files: lines marked both comment+blank=%d" % double_marked)
out.extend(sample_double)

# ---- independent token check on 5 random files ----
import random
random.seed(7)
sample = random.sample(processed, 5)
for f in sample:
    content = zf.read(f["path"])
    with repo._parser_lock:
        tree = repo.parser.parse(content)
    nodes = list(_walk(tree.root_node))
    comments = [(n.start_byte, n.end_byte,
                 bool(SECURITY_COMMENT.search(_decode(content[n.start_byte:n.end_byte]))))
                for n in nodes if n.type == "comment"]
    protected = [(n.start_byte, n.end_byte) for n in nodes if n.type in STRING_TYPES]
    offsets = _offsets(content)
    rows, omissions = repo._clean(content, 0, len(content), offsets, comments, protected)
    orig_t = len(enc.encode(content.decode("utf-8", "replace")))
    clean_t = len(enc.encode("\n".join(r["text"] for r in rows)))
    orig_l = content.count(b"\n") + (0 if content.endswith(b"\n") or not content else 1)
    out.append("%s: lines %d->%d tok %d->%d" %
               (f["path"].split("/")[-1], orig_l, len(rows), orig_t, clean_t))

# ---- Lab30: confirm the 3 slice blank lines are boundary artifacts ----
s30 = json.loads((DATA / "snapshot_lab30.json").read_text(encoding="utf-8"))
z30 = zipfile.ZipFile(DATA / "lab30-app-audit.zip")
slice_blank = set()
for u in s30["units"]:
    for o in u["omissions"]:
        slice_blank.add((u["file_path"], o["start_line"]))
out.append("Lab30 slice-level blank records: %s" % sorted(slice_blank))
for path, ln in slice_blank:
    content = z30.read(path)
    offsets = _offsets(content)
    ls = offsets[ln - 1]
    le = offsets[ln] if ln < len(offsets) else len(content)
    out.append("  %s line %d full content=[%s]" % (path.split("/")[-1], ln,
                                                    content[ls:le].rstrip(b"\r\n").decode("utf-8", "replace")))

(DATA / "verify_v2.txt").write_text("\n".join(out), encoding="utf-8")
print("done")
