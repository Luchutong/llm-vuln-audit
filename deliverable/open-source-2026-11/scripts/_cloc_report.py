import json, subprocess, sys

ROOT = "/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main"
EXCL = "node_modules,.venv,__pycache__,dist,.pytest_cache,data,coverage,htmlcov"
CODE_LANGS = {"Python", "TypeScript", "PHP", "CSS", "JavaScript", "SVG", "Bourne Shell",
              "Bourne Again Shell", "Dockerfile", "YAML", "TOML", "INI", "Markdown"}
SRC_LANGS = {"Python", "TypeScript", "PHP", "CSS", "JavaScript"}


def cloc(paths):
    cmd = ["cloc", *paths, "--exclude-dir=" + EXCL, "--json", "--quiet"]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True).stdout
    return json.loads(out or "{}")


def langs(d):
    return {k: v for k, v in d.items()
            if isinstance(v, dict) and "nFiles" in v and k != "SUM"}


def agg(d, allowed):
    f = sum(v["nFiles"] for k, v in langs(d).items() if k in allowed)
    c = sum(v["code"] for k, v in langs(d).items() if k in allowed)
    b = sum(v["blank"] for k, v in langs(d).items() if k in allowed)
    m = sum(v["comment"] for k, v in langs(d).items() if k in allowed)
    return f, b, m, c


dirs = ["backend", "frontend/src", "labs/lab30", "poc_runner"]
print("### PER-DIR")
for p in dirs:
    d = cloc([p])
    fa, ba, ma, ca = agg(d, CODE_LANGS)
    fs, bs, ms, cs = agg(d, SRC_LANGS)
    print(f"{p}\tall={fa}\t{ba}\t{ma}\t{ca}\tsrc={fs}\t{cs}")

print("### TOTAL")
d = cloc(dirs)
fa, ba, ma, ca = agg(d, CODE_LANGS)
fs, bs, ms, cs = agg(d, SRC_LANGS)
print(f"TOTAL\tall={fa}\t{ba}\t{ma}\t{ca}\tsrc={fs}\t{cs}")

print("### BY-LANG")
for k, v in sorted(langs(d).items(), key=lambda x: -x[1]["code"]):
    print(f"{k}\t{v['nFiles']}\t{v['blank']}\t{v['comment']}\t{v['code']}")

print("### RAW-DIRS-ALL")
for p in dirs:
    d = cloc([p])
    s = d.get("SUM") or {}
    print(f"{p}\tfiles={s.get('nFiles')}\tcode={s.get('code')}")
