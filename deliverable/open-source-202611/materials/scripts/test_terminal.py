#!/usr/bin/env python3
import sys
sys.path.insert(0, r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import")
from render_lib import terminal_window

lines = [
    ("aurora@lab:~$ docker compose ps", (130, 220, 140)),
    "NAME                          SERVICE          STATUS                    PORTS",
    "vuln-audit-lab30-1            lab30            Up 31 minutes (healthy)   127.0.0.1:18880->80/tcp",
    "vuln-audit-lab30-db-1         lab30-db         Up 31 minutes (healthy)",
    "vuln-audit-lab30-fixtures-1   lab30-fixtures   Up 31 minutes (healthy)",
    "vuln-audit-poc-runner-1       poc-runner       Up 31 minutes",
]
out = r"C:\Users\Aurora\Doubao\chats\2026-11-08\new-chat\llm-vuln-audit\data\part-c-import\shots\term_test.png"
img = terminal_window(lines, "aurora@ubuntu: ~/llm-vuln-audit")
img.save(out)
print("saved", img.size)
