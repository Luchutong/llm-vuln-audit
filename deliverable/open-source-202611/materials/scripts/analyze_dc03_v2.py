#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-C03 v2: authoritative cleaning stats.

File-level cleaning is obtained by calling the production SourceRepository._clean
on the whole file (not reconstructed from slices). Slice-level stats reuse the
frozen snapshot units (real model inputs). Token metric: tiktoken cl100k_base.
"""
import json
import sys
import zipfile
from pathlib import Path

import tiktoken
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
sys.path.insert(0, str(REPO / "backend"))
from audit.source import SourceRepository, _offsets, _walk, _decode  # noqa: E402

DATA = REPO / "data" / "part-c-import"
OUTDIR = REPO / "deliverable" / "open-source-202611" / "runs"
OUTDIR.mkdir(parents=True, exist_ok=True)

enc = tiktoken.get_encoding("cl100k_base")
plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

# Reuse the production parser; storage path is irrelevant for method calls.
repo = SourceRepository(Path(r"C:\pmf_audit"))

TARGETS = [
    {"key": "lab30", "name": "Lab30 靶场（lab30-shop）",
     "snap": DATA / "snapshot_lab30.json", "zip": DATA / "lab30-app-audit.zip"},
    {"key": "phpmyfaq", "name": "phpMyFAQ 4.1.1",
     "snap": DATA / "snapshot_full.json", "zip": DATA / "phpmyfaq-4.1.1-audit.zip"},
]


def pct(new, old):
    return round(100.0 * (old - new) / old, 2) if old else 0.0


def quantiles(xs):
    xs = sorted(xs)
    n = len(xs)

    def q(p):
        if n == 1:
            return xs[0]
        i = p * (n - 1)
        lo = int(i)
        hi = min(lo + 1, n - 1)
        return round(xs[lo] + (xs[hi] - xs[lo]) * (i - lo), 1)

    return {"min": xs[0], "p25": q(0.25), "median": q(0.5),
            "mean": round(sum(xs) / n, 1), "p75": q(0.75),
            "p95": q(0.95), "max": xs[-1]}


def whole_file_clean(content):
    """Call production extraction + _clean on the whole file (authoritative)."""
    with repo._parser_lock:
        tree = repo.parser.parse(content)
    nodes = list(_walk(tree.root_node))
    from audit.source import SECURITY_COMMENT, STRING_TYPES
    comments = [(n.start_byte, n.end_byte,
                 bool(SECURITY_COMMENT.search(_decode(content[n.start_byte:n.end_byte]))))
                for n in nodes if n.type == "comment"]
    protected = [(n.start_byte, n.end_byte) for n in nodes if n.type in STRING_TYPES]
    offsets = _offsets(content)
    rows, omissions = repo._clean(content, 0, len(content), offsets, comments, protected)
    return rows, omissions


def analyze(t):
    snap = json.loads(t["snap"].read_text(encoding="utf-8"))
    zf = zipfile.ZipFile(t["zip"])
    names = set(zf.namelist())
    files = snap["files"]
    units = snap["units"]
    processed = [f for f in files if f["is_php"] and not f.get("excluded")]

    orig_lines = orig_bytes = orig_tok = 0
    clean_lines = clean_tok = 0
    blank = comment = 0
    per_file = {}

    for f in processed:
        path = f["path"]
        raw = zf.read(path) if path in names else b""
        n_orig_lines = raw.count(b"\n") + (0 if raw.endswith(b"\n") or not raw else 1)
        n_orig_tok = len(enc.encode(raw.decode("utf-8", errors="replace")))
        orig_lines += n_orig_lines
        orig_bytes += len(raw)
        orig_tok += n_orig_tok

        rows, omissions = whole_file_clean(raw)
        b = sum(1 for o in omissions if o["reason"] == "blank_line")
        c = sum(1 for o in omissions if o["reason"] == "irrelevant_comment")
        cleaned_text = "\n".join(r["text"] for r in rows)
        n_clean_tok = len(enc.encode(cleaned_text))
        clean_lines += len(rows)
        clean_tok += n_clean_tok
        blank += b
        comment += c
        per_file[path] = {"orig_lines": n_orig_lines, "clean_lines": len(rows),
                          "orig_tok": n_orig_tok, "clean_tok": n_clean_tok,
                          "blank": b, "comment": c}

    # slice level (real model inputs, from the frozen snapshot)
    sl_lines, sl_bytes, sl_tok, overlaps = [], [], [], []
    boundaries = {}
    for u in units:
        sl_lines.append(len(u["cleaned_lines"]))
        sl_bytes.append(u["end_byte"] - u["start_byte"])
        txt = "\n".join(cl["text"] for cl in u["cleaned_lines"])
        sl_tok.append(len(enc.encode(txt)))
        overlaps.append(u["slice_rule"].get("overlap_lines", 0))
        b = u["slice_rule"].get("boundary", "unknown")
        boundaries[b] = boundaries.get(b, 0) + 1

    return {
        "name": t["name"], "snapshot_id": snap["id"],
        "archive_sha256": snap["archive_sha256"], "stats": snap["stats"],
        "file_level": {
            "processed_php_files": len(processed),
            "orig_lines": orig_lines, "clean_lines": clean_lines,
            "orig_bytes": orig_bytes, "orig_tok": orig_tok, "clean_tok": clean_tok,
            "blank_removed": blank, "comment_removed": comment,
            "line_reduction_pct": pct(clean_lines, orig_lines),
            "tok_reduction_pct": pct(clean_tok, orig_tok),
        },
        "slice_level": {
            "slice_count": len(units),
            "slice_lines_dist": quantiles(sl_lines),
            "slice_bytes_dist": quantiles(sl_bytes),
            "slice_tok_dist": quantiles(sl_tok),
            "total_slice_tok": sum(sl_tok),
            "overlap_extra_tok": sum(sl_tok) - clean_tok,
            "boundaries": boundaries,
            "slices_with_overlap": sum(1 for o in overlaps if o > 0),
        },
        "_arrays": {"lines": sl_lines, "tok": sl_tok, "bytes": sl_bytes},
        "_per_file": per_file,
    }


def make_hist(r):
    key = "lab30" if "Lab30" in r["name"] else "phpmyfaq"
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    axes[0].hist(r["_arrays"]["lines"], bins=20, color="#3b6ea5", edgecolor="white")
    axes[0].set_title("%s 切片行数分布" % r["name"])
    axes[0].set_xlabel("每个切片清洗后行数")
    axes[0].set_ylabel("切片数")
    m = r["slice_level"]["slice_lines_dist"]["mean"]
    axes[0].axvline(m, color="#c0392b", linestyle="--", label="均值 %.0f" % m)
    axes[0].legend()
    axes[1].hist(r["_arrays"]["tok"], bins=20, color="#2e8b57", edgecolor="white")
    axes[1].set_title("%s 切片 token 分布 (cl100k_base)" % r["name"])
    axes[1].set_xlabel("每个切片 LLM token 数")
    axes[1].set_ylabel("切片数")
    mt = r["slice_level"]["slice_tok_dist"]["mean"]
    axes[1].axvline(mt, color="#c0392b", linestyle="--", label="均值 %.0f" % mt)
    axes[1].legend()
    fig.tight_layout()
    p = OUTDIR / ("D-C03_%s_切片直方图.png" % key)
    fig.savefig(p, dpi=150)
    plt.close(fig)
    return p


results = []
for t in TARGETS:
    r = analyze(t)
    r["histogram"] = str(make_hist(r))
    results.append(r)

slim = [{k: v for k, v in r.items() if k not in ("_arrays", "_per_file")} for r in results]
(OUTDIR / "D-C03_清洗切片统计.json").write_text(
    json.dumps(slim, ensure_ascii=False, indent=2), encoding="utf-8")

# also persist per-file detail for traceability (ignored data dir)
(DATA / "dc03_per_file.json").write_text(
    json.dumps({r["name"]: r["_per_file"] for r in results}, ensure_ascii=False),
    encoding="utf-8")

for r in results:
    fl, sl = r["file_level"], r["slice_level"]
    print("=== %s ===" % r["name"])
    print(" files=%d slices=%d" % (fl["processed_php_files"], sl["slice_count"]))
    print(" lines %d->%d (-%s%%)" % (fl["orig_lines"], fl["clean_lines"], fl["line_reduction_pct"]))
    print(" tokens %d->%d (-%s%%)" % (fl["orig_tok"], fl["clean_tok"], fl["tok_reduction_pct"]))
    print(" blank=%d comment=%d" % (fl["blank_removed"], fl["comment_removed"]))
    print(" boundary=%s" % json.dumps(sl["boundaries"], ensure_ascii=False))
    print(" total_slice_tok=%d overlap_extra=%d" % (sl["total_slice_tok"], sl["overlap_extra_tok"]))
print("DONE")
