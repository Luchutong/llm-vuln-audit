#!/usr/bin/env python3
"""Offline host-queue UI acceptance: every API is intercepted in memory."""
import argparse
import copy
import os
from pathlib import Path

from playwright.sync_api import expect, sync_playwright
from ui_fixtures import COMPLETED_ID, PROJECT_ID, SNAPSHOT_ID, sources_api
from ui_smoke import Checks, close_dialog, goto, no_overflow, open_logs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base')
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    api, checks = sources_api(), Checks()
    full = dict(responses=512, tools=4096, seconds=3600)
    quick = dict(responses=256, tools=2048, seconds=1800)
    item = api.runs[COMPLETED_ID]
    item.update(run_limits=full, poc_mode='auto', poc_policy=dict(mode='auto', runtime='claude_sdk',
                sdk_requests=dict(version='sdk-requests-v1', execute=40, conclude=3)))
    item['task_spec'].update(orchestration_policy='host-queue-v1', completion_policy='coverage_review',
                             workflow_policy='discovery_first', review_policy='batch-v1')
    item['execution_summary'] = dict(phase='review', run_limits=full,
        run_usage=dict(responses=194, tools=274, seconds=1016), run_remaining=dict(responses=318, tools=3822, seconds=2584),
        active_executions=[], blocked_task_ids=[], poc=dict(mode='auto', available=True),
        workflow=dict(version='host-queue-v1', source='derived', stage='review',
            limits=dict(discovery=350, poc=130, review=32), used=dict(discovery=138, poc=46, review=10),
            remaining=dict(discovery=212, poc=84, review=22), transferred=20, review_reserved_seconds=240,
            review_reserve=dict(pending_items=23, estimated_batches=3, workers=0, responses=9, seconds=240, funded=True)),
        directions=dict(total=24, required_total=15, unsettled_total=0, unsettled_required_total=0,
                        pending_total=0, assigned_total=0, advisory_total=9),
        verification=dict(total=23, pending=17, verified=6, reviewed=6, pending_review=0))
    def handle(route):
        path = route.request.url.split('/api/', 1)[1].split('?', 1)[0]
        if path == 'config':
            config = api.config()
            config['run_budget_limits']['profiles'] = dict(goal=quick, coverage_review=full)
            api.json(route, config)
        elif path.endswith('/report') and 'format=' in route.request.url:
            route.fulfill(status=200, content_type='application/octet-stream', body='offline frozen report',
                          headers={'Content-Disposition': 'attachment; filename="offline-report.txt"'})
        elif path.endswith('/final-review'):
            api.json(route, dict(schema_version='final-review/v1', provenance=dict(immutable=True),
                counts=dict(raw_records=29, valid_records=29, canonical=23, withdrawn=0, accepted=0, pending=23, contested=0),
                run_outcome=dict(status='inconclusive', audit_complete=False),
                quality_result=dict(report_kind='partial', publishability='releasable_partial', failed_checks=[]),
                coverage=dict(files=dict(total=69, read=47, reviewed=47, skipped=0, pending=22, complete=False),
                    directions=dict(total=24, required=15, advisory=9, resolved=15, skipped=0, unsettled=0, complete=True),
                    verification=dict(total=23, verified=6, pending=17)),
                review_batch=dict(item_refs=[None]*23, decisions=[None]*23, unresolved_items=[]),
                review_batches=dict(batches=[]),
                canonical_findings=[dict(canonical_id=f'claim-{i}', final_disposition='pending', frozen_claim=dict(title=f'待补证结论 {i}', category='sqli', file_path='src/a.php')) for i in range(23)],
                advisory_directions=[dict(id=f'dir-{i}', text='后续可单独补充业务条件取证。') for i in range(9)], action_items=[]))
        elif route.request.method != 'GET':
            raise AssertionError('Unexpected mutation: ' + route.request.url)
        else:
            api.handle(route)
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.environ.get('CHROME_BIN'))
        page = browser.new_page(viewport=dict(width=1440, height=1000))
        page.set_default_timeout(10000)
        errors = []
        page.on('pageerror', lambda exc: errors.append(str(exc)))
        page.route('**/api/**', handle)
        try:
            goto(page, args.base, f'#sources/{PROJECT_ID}/new?snapshot={SNAPSHOT_ID}')
            expect(page.get_by_text('整次上限：模型 512 次', exact=False)).to_be_visible()
            page.get_by_role('combobox', name='审计模式', exact=True).select_option('goal')
            expect(page.get_by_text('整次上限：模型 256 次', exact=False)).to_be_visible()
            page.get_by_role('combobox', name='审计模式', exact=True).select_option('coverage_review')
            page.get_by_role('button', name='高级执行设置', exact=True).click()
            dialog = page.get_by_role('dialog', name='高级执行设置')
            expect(dialog.get_by_role('spinbutton', name='整次模型请求上限', exact=False)).to_have_value('512')
            expect(dialog.get_by_role('spinbutton', name='Planner 最大回合', exact=False)).to_have_count(0)
            expect(dialog).to_contain_text('自动分配')
            close_dialog(page)
            checks.passed('fresh full/quick defaults follow the mode; host-queue has no round ceiling input')
            goto(page, args.base, f'#run/{COMPLETED_ID}')
            status = page.get_by_role('region', name='执行预算与验证策略')
            expect(status).to_contain_text('宿主调度 · 统一终审')
            expect(status).to_contain_text('待终审 23 项 · 预计 3 批 · 当前预留 9 次请求')
            expect(status).to_contain_text('必做未决方向 0')
            expect(status).to_contain_text('后续建议 9（不阻止收束）')
            expect(status).to_contain_text('单条自动验证配置：实验最多 40 次请求 · 结论最多 3 次请求')
            checks.passed('frozen SDK quotas are distinct from source agent limits')
            for theme in ('dark', 'light'):
                page.set_viewport_size(dict(width=1440, height=1000))
                if page.locator('html').get_attribute('data-theme') != theme:
                    page.get_by_role('button', name=f"切换{'深' if theme == 'dark' else '浅'}色主题", exact=True).click()
                for width in (1440, 1024, 768, 390):
                    page.set_viewport_size(dict(width=width, height=1000))
                    status.scroll_into_view_if_needed()
                    expect(status.locator('[data-stage="review"]')).to_be_visible()
                    no_overflow(page, f'host queue {theme} {width}', checks)
                    if args.screenshots:
                        page.screenshot(path=str(args.screenshots / f'host-queue-{theme}-{width}.png'))
            page.set_viewport_size(dict(width=1440, height=1000))
            dialog = open_logs(page)
            expect(dialog).to_be_visible()
            dialog.get_by_role('tab', name='结果报告', exact=True).click()
            facts = dialog.get_by_role('region', name='终审事实包')
            expect(facts).to_contain_text('规范结论：23')
            expect(facts).to_contain_text('逐项终审已处置 23/23')
            expect(facts).to_contain_text('必做方向结算 15/15 · 后续建议 9')
            for width in (1440, 1024, 768, 390):
                page.set_viewport_size(dict(width=width, height=1000))
                no_overflow(page, f'frozen report {width}', checks)
            page.set_viewport_size(dict(width=1440, height=1000))
            for name in ('JSON', '证据包'):
                link = dialog.get_by_role('link', name=name, exact=True)
                expect(link).to_be_visible()
                with page.expect_download() as download:
                    link.click()
                assert download.value.suggested_filename == 'offline-report.txt'
            close_dialog(page)
            checks.passed('logs and frozen report downloads remain accessible')
            # Explicit historical settings survive cloning; reset is a separate action.
            old = api.runs[COMPLETED_ID]
            old['task_spec'].update(orchestration_policy='rounds-v1', workflow_policy='discovery_first',
                                   workflow_limits=dict(discovery=220, poc=0, review=36))
            old['run_limits'] = quick
            old['execution_summary'] = copy.deepcopy(old['execution_summary'])
            old['execution_summary']['workflow']['version'] = 'discovery-first-v1'
            page.reload()
            page.get_by_role('button', name='基于此任务新建', exact=True).click()
            expect(page.get_by_text('整次上限：模型 256 次', exact=False)).to_be_visible()
            page.get_by_role('button', name='高级执行设置', exact=True).click()
            dialog = page.get_by_role('dialog', name='高级执行设置')
            expect(dialog.get_by_role('spinbutton', name='Planner 最大回合', exact=False)).to_be_visible()
            expect(dialog.get_by_role('spinbutton', name='验证复核与收束请求配额', exact=False)).to_have_value('36')
            dialog.get_by_role('button', name='使用当前默认配置', exact=True).click()
            expect(dialog.get_by_role('spinbutton', name='整次模型请求上限', exact=False)).to_have_value('512')
            expect(dialog.get_by_role('spinbutton', name='Planner 最大回合', exact=False)).to_have_count(0)
            close_dialog(page)
            checks.passed('historical cloning preserves budgets/policy/fixed allocation until explicit reset')
            assert not errors, errors
            assert not api.unexpected, api.unexpected
            print(f'PASS {checks.count} host queue browser checks; intercepted APIs only')
        finally:
            browser.close()


if __name__ == '__main__':
    main()
