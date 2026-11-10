#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-C03: cleaning + slicing statistics, reusing the production snapshot.

Token metric: tiktoken cl100k_base (real LLM BPE). Physical lines and bytes are
reported alongside. Two scopes:
  - file level (deduplicated): true cleaning effect
  - slice level (actual model inputs, includes overlap): real request cost
"""
import json
import zipfile
from pathlib import Path

import tiktoken
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO = Path(r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit")
DATA = REPO / "data" / "part-c-import"
OUTDIR = REPO / "deliverable" / "open-source-202611" / "runs"
OUTDIR.mkdir(parents=True, exist_ok=True)

enc = tiktoken.get_encoding("cl100k_base")

# Chinese font for matplotlib
plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

TARGETS = [
    {
        "key": "lab30",
        "name": "Lab30 靶场（lab30-shop）",
        "snap": DATA / "snapshot_lab30.json",
        "zip": DATA / "lab30-app-audit.zip",
    },
    {
        "key": "phpmyfaq",
        "name": "phpMyFAQ 4.1.1",
        "snap": DATA / "snapshot_full.json",
        "zip": DATA / "phpmyfaq-4.1.1-audit.zip",
    },
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

    return {
        "min": xs[0], "p25": q(0.25), "median": q(0.5),
        "mean": round(sum(xs) / n, 1), "p75": q(0.75),
        "p95": q(0.95), "max": xs[-1],
    }


def analyze(t):
    snap = json.loads(t["snap"].read_text(encoding="utf-8"))
    zf = zipfile.ZipFile(t["zip"])
    zip_names = set(zf.namelist())

    files = snap["files"]
    units = snap["units"]
    processed = [f for f in files if f["is_php"] and not f.get("excluded")]

    # ---- file level (deduplicated) ----
    orig_lines = orig_bytes = orig_tok = 0
    clean_lines = clean_tok = 0
    blank = irrelevant = 0
    per_file = {}

    # group units by file
    by_file = {}
    for u in units:
        by_file.setdefault(u["file_path"], []).append(u)

    for f in processed:
        path = f["path"]
        raw = zf.read(path) if path in zip_names else b""
        n_orig_lines = raw.count(b"\n") + (0 if raw.endswith(b"\n") or not raw else 1)
        n_orig_tok = len(enc.encode(raw.decode("utf-8", errors="replace")))
        orig_lines += n_orig_lines
        orig_bytes += len(raw)
        orig_tok += n_orig_tok

        # dedupe cleaned lines by line number
        line_map = {}
        om = set()
        for u in by_file.get(path, []):
            for cl in u["cleaned_lines"]:
                line_map[cl["number"]] = cl["text"]
            for o in u["omissions"]:
                om.add((o["start_line"], o["reason"]))
        kept_nums = sorted(line_map)
        cleaned_text = "\n".join(line_map[k] for k in kept_nums)
        n_clean_tok = len(enc.encode(cleaned_text))
        clean_lines += len(kept_nums)
        clean_tok += n_clean_tok
        b = sum(1 for _, r in om if r == "blank_line")
        c = sum(1 for _, r in om if r == "irrelevant_comment")
        blank += b
        irrelevant += c
        per_file[path] = {
            "orig_lines": n_orig_lines, "clean_lines": len(kept_nums),
            "orig_tok": n_orig_tok, "clean_tok": n_clean_tok,
            "blank": b, "comment": c,
        }

    # ---- slice level (actual model inputs) ----
    sl_lines, sl_bytes, sl_tok, overlaps = [], [], [], []
    boundaries = {}
    for u in units:
        nl = len(u["cleaned_lines"])
        sl_lines.append(nl)
        sl_bytes.append(u["end_byte"] - u["start_byte"])
        txt = "\n".join(cl["text"] for cl in u["cleaned_lines"])
        sl_tok.append(len(enc.encode(txt)))
        overlaps.append(u["slice_rule"].get("overlap_lines", 0))
        b = u["slice_rule"].get("boundary", "unknown")
        boundaries[b] = boundaries.get(b, 0) + 1

    result = {
        "name": t["name"],
        "snapshot_id": snap["id"],
        "archive_sha256": snap["archive_sha256"],
        "stats": snap["stats"],
        "file_level": {
            "processed_php_files": len(processed),
            "orig_lines": orig_lines, "clean_lines": clean_lines,
            "orig_bytes": orig_bytes,
            "orig_tok": orig_tok, "clean_tok": clean_tok,
            "blank_removed": blank, "comment_removed": irrelevant,
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
    return result


def make_hist(result):
    key = "lab30" if "Lab30" in result["name"] else "phpmyfaq"
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    axes[0].hist(result["_arrays"]["lines"], bins=20, color="#3b6ea5", edgecolor="white")
    axes[0].set_title("%s 切片行数分布" % result["name"])
    axes[0].set_xlabel("每个切片清洗后行数")
    axes[0].set_ylabel("切片数")
    axes[0].axvline(result["slice_level"]["slice_lines_dist"]["mean"], color="#c0392b",
                    linestyle="--", label="均值 %.0f" % result["slice_level"]["slice_lines_dist"]["mean"])
    axes[0].legend()

    axes[1].hist(result["_arrays"]["tok"], bins=20, color="#2e8b57", edgecolor="white")
    axes[1].set_title("%s 切片 token 分布 (cl100k_base)" % result["name"])
    axes[1].set_xlabel("每个切片 LLM token 数")
    axes[1].set_ylabel("切片数")
    axes[1].axvline(result["slice_level"]["slice_tok_dist"]["mean"], color="#c0392b",
                    linestyle="--", label="均值 %.0f" % result["slice_level"]["slice_tok_dist"]["mean"])
    axes[1].legend()
    fig.tight_layout()
    p = OUTDIR / ("D-C03_%s_切片直方图.png" % key)
    fig.savefig(p, dpi=150)
    plt.close(fig)
    return p


results = []
for t in TARGETS:
    r = analyze(t)
    hp = make_hist(r)
    r["histogram"] = str(hp)
    results.append(r)

# save machine-readable stats (drop heavy arrays/per-file for the committed JSON)
slim = []
for r in results:
    rr = {k: v for k, v in r.items() if k not in ("_arrays", "_per_file")}
    slim.append(rr)
(OUTDIR / "D-C03_清洗切片统计.json").write_text(
    json.dumps(slim, ensure_ascii=False, indent=2), encoding="utf-8")

# console summary
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
