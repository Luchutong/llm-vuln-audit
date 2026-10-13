#!/usr/bin/env python3
"""Exercise the human verification gate against a real finding.

The rules under test are the ones that keep a failed POC run from being laundered into a
verdict, so each is checked twice: once that the server refuses the bad combination, and
once that it accepts the honest one. A gate that only rejects is easy to satisfy by
rejecting everything.

Usage: verify_gate.py <base-url> <run-id>
"""
import io
import json
import sys

import httpx

base = sys.argv[1].rstrip("/")
run_id = sys.argv[2]
client = httpx.Client(base_url=base, timeout=30)

detail = client.get(f"/api/runs/{run_id}").json()
findings = [f for f in detail["findings"] if f.get("validation_state") == "candidate"]
if not findings:
    raise SystemExit("this run has no validated candidate; nothing to verify against")

by_category = {f["category"]: f for f in findings}
print("validated candidates:", {f["category"]: f["id"][:8] for f in findings})

failures: list[str] = []


def post(finding_id: str, payload: dict, files: list[tuple[str, bytes]] | None = None):
    data = {"record": json.dumps(payload)}
    handles = [("files", (name, io.BytesIO(body), "text/plain")) for name, body in (files or [])]
    return client.post(f"/api/findings/{finding_id}/verifications", data=data, files=handles)


def expect_status(label: str, response, wanted: int):
    ok = response.status_code == wanted
    print(f"  {'ok ' if ok else 'FAIL'} {label}: {response.status_code}")
    if not ok:
        failures.append(f"{label}: expected {wanted}, got {response.status_code} {response.text[:200]}")
    return ok


# --- shape validation -------------------------------------------------------
any_finding = findings[0]["id"]
print("\nmalformed submissions")
expect_status("bad verdict", post(any_finding, {"verdict": "maybe", "execution_status": "success"}), 400)
expect_status("bad execution_status", post(any_finding, {"verdict": "uncertain", "execution_status": "worked"}), 400)
expect_status("missing record fields", post(any_finding, {}), 400)

# --- the rule that matters most ---------------------------------------------
print("\nexecution errors never become an exclusion")
expect_status(
    "rejected while syntax_error",
    post(any_finding, {"verdict": "rejected", "execution_status": "syntax_error"}),
    400,
)
expect_status(
    "rejected while not_triggered",
    post(any_finding, {"verdict": "rejected", "execution_status": "not_triggered"}),
    400,
)
expect_status(
    "uncertain while not_triggered is allowed",
    post(any_finding, {"verdict": "uncertain", "execution_status": "not_triggered", "notes": "环境不匹配"}),
    200,
)

print("\nconfirmation must carry a reproducible control experiment")
expect_status(
    "confirmed without normal/attack observations",
    post(any_finding, {"verdict": "confirmed", "execution_status": "success"}),
    400,
)


def confirmed_record(**overrides) -> dict:
    payload = {
        "verdict": "confirmed",
        "execution_status": "success",
        "attack_observation": "攻击输入产生了可观察差异",
        "normal_observation": "正常输入没有产生该差异",
        "target_version": "DVWA 2.5 @ a96943dc",
        "command": "php poc.php",
        "modified_script": "原样运行，未修改",
    }
    payload.update(overrides)
    return payload

# --- the XSS-specific gate --------------------------------------------------
xss = by_category.get("xss_r")
if xss is None:
    print("\nno reflected-XSS candidate in this run; skipping the browser-evidence gate")
else:
    print("\nreflected XSS needs browser evidence, not just a payload in the response")
    expect_status(
        "xss confirmed without browser_execution",
        post(xss["id"], confirmed_record(attack_observation="响应中出现 <script>"),
             files=[("xss-evidence.txt", b"browser log placeholder\n")]),
        400,
    )
    expect_status(
        "xss confirmed with browser_execution but no attachment",
        post(
            xss["id"],
            confirmed_record(attack_observation="响应中出现 <script>", browser_execution=True),
        ),
        400,
    )
    response = post(
        xss["id"],
        confirmed_record(
            attack_observation="payload 在浏览器中执行，弹出 alert(1)，控制台可见对话框",
            browser_execution=True,
            command="chromium --headless --dump-dom 'http://127.0.0.1:4280/vulnerabilities/xss_r/?name=<script>alert(1)</script>'",
        ),
        files=[("xss-evidence.txt", b"dialog opened: alert(1) at xss_r low.php line 8\n")],
    )
    expect_status("xss confirmed with browser evidence + attachment", response, 200)
    if response.status_code == 200:
        # The endpoint answers with the finding, not the verification: the record that was
        # just added is the newest one hanging off it.
        record = (response.json().get("verifications") or [{}])[-1]
        stored = record.get("files") or []
        print("   stored files:", [item["stored"] for item in stored])
        if not stored:
            failures.append("the attachment was accepted but nothing was recorded against it")
        for item in stored:
            got = client.get(item["url"])
            print(f"   fetch {item['url']} -> {got.status_code} {len(got.content)} bytes")
            if got.status_code != 200 or not got.content:
                failures.append(f"uploaded evidence not retrievable at {item['url']}")

# --- a normal acceptance, and that it sticks --------------------------------
print("\na well-formed submission is accepted and changes the finding")
target = by_category.get("sqli") or findings[0]
response = post(
    target["id"],
    {
        "verdict": "confirmed",
        "execution_status": "success",
        "attack_observation": "id=1' OR '1'='1 返回全部用户记录，共 5 行",
        "normal_observation": "id=1 只返回 admin 一行",
        "target_version": "DVWA 2.5 @ a96943dc, MariaDB 分支",
        "command": "php scripts/sqli_low_poc.php",
        "modified_script": "$BASE 改成本机 127.0.0.1:4280",
        "modification_notes": "仅改动基址",
        "browser_execution": False,
    },
    files=[("sqli-run.log", b"normal: 1 row\nattack: 5 rows\n")],
)
expect_status("confirmed with observation + log", response, 200)

after = client.get(f"/api/runs/{run_id}").json()
record = next((f for f in after["findings"] if f["id"] == target["id"]), None)
if record is None:
    failures.append("finding vanished from the run after verification")
else:
    verdicts = [v["verdict"] for v in record.get("verifications", [])]
    print("  verifications on record:", verdicts)
    if "confirmed" not in verdicts:
        failures.append(f"verification was not stored on the finding: {verdicts}")
    metrics = after["metrics"]
    print(
        "  metrics now:",
        {k: metrics[k] for k in ("confirmed", "rejected", "uncertain", "awaiting_verification", "verification_coverage")},
    )
    if metrics["confirmed"] < 1:
        failures.append("metrics.confirmed did not move after a confirmed verification")

if failures:
    print("\nFAILURES:")
    for item in failures:
        print(" -", item)
    raise SystemExit(1)
print("\nthe verification gate behaves as specified")
