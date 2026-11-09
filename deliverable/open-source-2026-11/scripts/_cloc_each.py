import json, subprocess
ROOT = "/home/zsh/桌面/llm-vuln-audit-main (4)/llm-vuln-audit-main"
EXCL = "node_modules,.venv,__pycache__,dist,.pytest_cache,data,coverage,htmlcov"
for p in ["backend", "frontend/src", "labs/lab30", "poc_runner", "frontend"]:
    excl = EXCL if p != "frontend" else "node_modules,dist,.vite,coverage"
    out = subprocess.run(["cloc", p, "--exclude-dir=" + excl, "--json", "--quiet"],
                         cwd=ROOT, capture_output=True, text=True).stdout
    d = json.loads(out or "{}")
    s = d.get("SUM") or {}
    print(f"### {p}  SUM files={s.get('nFiles')} blank={s.get('blank')} comment={s.get('comment')} code={s.get('code')}")
    for k, v in sorted(((k, v) for k, v in d.items() if isinstance(v, dict) and "nFiles" in v and k != "SUM"),
                       key=lambda x: -x[1]["code"]):
        print(f"    {k:<24}{v['nFiles']:>5}{v['blank']:>7}{v['comment']:>7}{v['code']:>8}")
