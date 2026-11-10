import json
import sys
import zipfile
from collections import Counter
from pathlib import Path

REPO = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
sys.path.insert(0, str(REPO / "backend"))
from audit.source import SourceRepository, _offsets, _walk, _decode, SECURITY_COMMENT, STRING_TYPES

DATA = REPO / "data" / "part-c-import"
repo = SourceRepository(Path(r"C:\pmf_audit"))
snap = json.loads((DATA / "snapshot_full.json").read_text(encoding="utf-8"))
zf = zipfile.ZipFile(DATA / "phpmyfaq-4.1.1-audit.zip")
processed = [f for f in snap["files"] if f["is_php"] and not f.get("excluded")]

total_events = 0
unique_lines = set()
multi = Counter()
for i, f in enumerate(processed):
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
    cc = Counter(o["start_line"] for o in omissions)
    for ln, k in cc.items():
        unique_lines.add((f["path"], ln))
        if k > 1:
            multi[(f["path"], ln)] = k
    total_events += len(omissions)

out = [
    "omission_events=%d" % total_events,
    "unique_lines_with_omission=%d" % len(unique_lines),
    "lines_with_multiple_events=%d" % len(multi),
    "sample_multi=%s" % list(multi.items())[:5],
]
(DATA / "omission_count.txt").write_text("\n".join(out), encoding="utf-8")
print("done")
