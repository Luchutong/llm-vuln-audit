#!/usr/bin/env python3
"""Merged prompt library, experiments and defence UI acceptance; all APIs intercepted.

Serve frontend/dist on an unused localhost port, then pass that URL. No live service,
model or database is used. The few writes in this test update in-memory fixtures only.
"""
from __future__ import annotations

import argparse
import os
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright
from ui_fixtures import COMPLETED_ID, STAMP, sources_api
from ui_smoke import Checks, goto, no_overflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    args = parser.parse_args()
    fixture = sources_api()
    prompts = [dict(id="P0-basic", label="内置基准", text="冻结的内置正文", reason="基准", issues=[],
                    phase="基础", builtin=True, used_by_runs=0, created_at=STAMP),
               dict(id="used", label="已用于审计", text="历史审计正文", reason="", issues=[],
                    phase="custom", builtin=False, used_by_runs=2, created_at=STAMP),
               dict(id="draft", label="可编辑草稿", text="草稿正文", reason="", issues=[],
                    phase="custom", builtin=False, used_by_runs=0, created_at=STAMP)]
    variants = [dict(id=name, label="证据链与交叉文件约束", phase="优化", focus="从源码核对调用链与前提条件。" * 4,
                     prompt="只使用已经读取的证据。") for name in ("P0-basic", "P1-evidence", "P2-crossfile")]
    rows = [dict(variant=v["id"], score=dict(TP=2, FP=1, FN=1, precision=2/3, recall=2/3, f1=2/3),
                 discipline=dict(reported=3, chain_rate=1.0), injection=dict(resisted=3, canaries=3, resistance_rate=1.0),
                 stats=dict(requests=6, tokens=800)) for v in variants]
    rows[0]["injection"].update(canaries=0, tested=0, total_canaries=3, unmeasured=3, resisted=0, resistance_rate=None)
    rows[1]["injection"].update(canaries=1, tested=1, total_canaries=3, unmeasured=2, resisted=1, resistance_rate=1.0)
    history = [dict(id="completed-experiment", status="completed", created_at=STAMP, finished_at=STAMP,
                    variants=[v["id"] for v in variants], units_limit=6, scenario=None, model="mock-model",
                    rows=rows, progress={}, error="")]
    fail_reads = [1]
    writes = []
    reviews = [dict(id="cross-check", finding_id=fixture.findings[COMPLETED_ID]["id"], revision=2,
                    decision="contested", rationale="脚本未核对对照身份，观测不支持当前结论。",
                    observed_normal="normal=member", observed_attack="attack=admin", created_at=STAMP)]
    fixture.findings[COMPLETED_ID]["verification_reviews"] = reviews
    fixture.detail_overrides[COMPLETED_ID] = {"verification_reviews": reviews, "defence": dict(
        score=0.75, denominator_weight=4, missing=["poc"],
        components=[dict(key="evidence", label="引用通过率", weight=2, value=1.0, source="run", detail="原始源码引用"),
                    dict(key="poc", label="POC验证率", weight=1, value=None, source="run", detail="未测量"),
                    dict(key="review", label="交叉复核率", weight=2, value=0.5, source="run", detail="Planner复核")],
        benchmark={}, note="评分用于解释机制覆盖，不是准确率。")}

    def handle(route):
        req = route.request
        path = urlsplit(req.url).path.removeprefix("/api")
        if path == "/prompts":
            if req.method == "GET":
                fixture.json(route, prompts)
            elif req.method == "POST":
                body = req.post_data_json
                writes.append((req.method, path, body))
                created = dict(body, id="derived", phase="custom", builtin=False, used_by_runs=0, created_at=STAMP)
                prompts.append(created)
                fixture.json(route, created, 201)
            else:
                raise AssertionError(f"Unexpected mock write {req.method} {path}")
        elif path.startswith("/prompts/") and req.method == "PUT":
            body = req.post_data_json
            writes.append((req.method, path, body))
            row = next(item for item in prompts if item["id"] == path.split("/")[-1])
            assert not row["builtin"] and not row["used_by_runs"]
            row.update(body)
            fixture.json(route, row)
        elif path == "/prompt-experiments/variants":
            fixture.json(route, variants)
        elif path == "/prompt-experiments" and req.method == "GET":
            if fail_reads[0]:
                fail_reads[0] -= 1
                fixture.json(route, {"detail": "模拟实验读取失败"}, 503)
            else:
                fixture.json(route, history)
        elif path == "/prompt-experiments" and req.method == "POST":
            body = req.post_data_json
            writes.append((req.method, path, body))
            active = dict(history[0], **body, id="running-experiment", status="running", rows=[])
            history.insert(0, active)
            fixture.json(route, active, 201)
        elif path.endswith("/cancel") and path.startswith("/prompt-experiments/"):
            writes.append((req.method, path, req.post_data_json))
            assert path == "/prompt-experiments/running-experiment/cancel"
            history[0]["status"] = "cancelled"
            fixture.json(route, history[0])
        elif req.method != "GET":
            raise AssertionError(f"Unexpected mock write {req.method} {path}")
        else:
            fixture.handle(route)

    checks = Checks()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.environ.get("CHROME_BIN"))
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.set_default_timeout(10000)
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.route("**/api/**", handle)
        goto(page, args.base, "#prompts")
        page.get_by_role("button", name="内置基准", exact=False).click()
        expect(page.get_by_role("textbox", name="正文", exact=False)).to_have_attribute("readonly", "")
        expect(page.get_by_role("button", name="没有改动", exact=True)).to_be_disabled()
        page.get_by_role("button", name="基于此版本另存", exact=True).click()
        page.get_by_role("textbox", name="标签", exact=True).fill("派生版本")
        page.get_by_role("textbox", name="正文", exact=False).fill("派生版本正文")
        page.get_by_role("button", name="保存新版本", exact=True).click()
        expect(page.get_by_role("status")).to_contain_text("已另存为新版本")
        assert writes[-1][2]["parent_id"] == "P0-basic"
        page.get_by_role("button", name="可编辑草稿", exact=False).click()
        page.get_by_role("textbox", name="正文", exact=False).fill("更新后的草稿正文")
        page.get_by_role("button", name="保存修改", exact=True).click()
        expect(page.get_by_role("status")).to_contain_text("已保存修改")
        page.get_by_role("button", name="已用于审计", exact=False).click()
        expect(page.get_by_role("textbox", name="正文", exact=False)).to_have_attribute("readonly", "")
        checks.passed("prompt versions can be derived and unused drafts edited; builtin and quoted text remain readonly")

        goto(page, args.base, "#experiments")
        expect(page.get_by_role("alert")).to_contain_text("模拟实验读取失败")
        page.get_by_role("button", name="重试读取", exact=True).click()
        expect(page.get_by_role("alert")).to_have_count(0)
        expect(page.get_by_role("table")).to_contain_text("防御得分")
        cells = page.locator("tbody tr").first.locator("td")
        expect(cells.nth(9)).to_have_text("未测量")
        expect(cells.nth(10)).to_have_text("—")
        expect(page.locator("tbody tr").nth(1)).to_contain_text("1/1 已测 · 2 未测")
        expect(page.get_by_role("link", name="下载 JSON", exact=True)).to_have_attribute("href", "/api/prompt-experiments/completed-experiment/report?format=json")
        page.get_by_role("button", name="开始对比", exact=True).click()
        expect(page.get_by_role("button", name="对比进行中…", exact=True)).to_be_disabled()
        page.locator(".records-prompt-row").filter(has_text="已完成").click()
        expect(page.get_by_role("button", name="查看进行中的实验", exact=True)).to_be_visible()
        page.wait_for_timeout(2800)
        expect(page.get_by_role("link", name="下载 JSON", exact=True)).to_be_visible()
        page.get_by_role("button", name="停止", exact=True).click()
        expect(page.get_by_role("button", name="开始对比", exact=True)).to_be_enabled()
        assert writes[-1][1] == "/prompt-experiments/running-experiment/cancel"
        checks.passed("experiment read errors recover, polling preserves historical selection and cancellation targets the active experiment")

        for theme in ("dark", "light"):
            page.set_viewport_size({"width": 1440, "height": 900})
            if page.locator("html").get_attribute("data-theme") != theme:
                page.get_by_role("button", name=f"切换{'深' if theme == 'dark' else '浅'}色主题", exact=True).click()
            for route_hash, ready in (("#prompts", "提示词库"), ("#experiments", "Prompt 实验")):
                goto(page, args.base, route_hash)
                expect(page.get_by_role("heading", name=ready, exact=True)).to_be_visible()
                for width in (1440, 1024, 768, 390):
                    page.set_viewport_size({"width": width, "height": 900})
                    no_overflow(page, f"{route_hash} {theme} {width}", checks)

        page.set_viewport_size({"width": 1440, "height": 900})
        goto(page, args.base, f"#run/{COMPLETED_ID}")
        page.get_by_role("button", name="查看防御评分明细", exact=True).click()
        dialog = page.get_by_role("dialog", name="审计详情", exact=True)
        expect(dialog).to_contain_text("0.750")
        expect(dialog).to_contain_text("未计入总分的成分：poc")
        dialog.get_by_role("tab", name="发现与验证", exact=True).click()
        dialog.get_by_role("button", name="Planner 比对核实", exact=False).click()
        expect(dialog).to_contain_text("观测不支持结论")
        expect(dialog).to_contain_text("复核第 2 版")
        expect(dialog).to_contain_text("normal=member")
        checks.passed("run defence explains missing components and cross-checks preserve revision, reason and observations")
        assert not errors, errors
        assert not fixture.unexpected, fixture.unexpected
        assert len(writes) == 4, writes
        browser.close()
    print(f"PASS {checks.count} merged feature browser checks; mock APIs only", flush=True)


if __name__ == "__main__":
    main()
