#!/usr/bin/env python3
"""Report views, per-finding scope, historical selection and download recovery (mock only)."""
import argparse
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright
from ui_fixtures import COMPLETED_ID, LEDGER_ID, STALE_LEDGER_ID, sources_api
from ui_run_presentation_smoke import facts
from ui_smoke import Checks, close_dialog, goto, no_overflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base')
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    api, checks = sources_api(), Checks()
    downloads, calls, errors = [], [], []
    held, hold_current = [], [False]
    failures = [True]
    api.runs[COMPLETED_ID]['status'] = 'inconclusive'
    historical_source = [True]
    api.findings[COMPLETED_ID]['cvss_assessment'] = dict(
        status='legacy_unrated', source='legacy', assessment_revision=1,
        conclusion_revision=api.findings[COMPLETED_ID]['revision'], metric_details={})
    def handle(route):
        url = urlsplit(route.request.url)
        path = url.path.removeprefix('/api')
        calls.append(path)
        if path.endswith('/final-review'):
            value = facts()
            value['counts'].update(canonical=2, accepted=1, pending=1, contested=0)
            value['run_outcome']['audit_complete'] = False
            value['run_outcome'].update(status='inconclusive', stop_reason=dict(code='final_review_incomplete',message='部分结论未完成终审，已确认漏洞报告已保留。'))
            finding = api.findings[COMPLETED_ID]
            value['canonical_findings'] = [dict(canonical_id='canonical-identity', final_disposition='accepted',
                current_claim_ref=dict(finding_id='different-source-record' if historical_source[0] else finding['id'],revision=finding['revision']),
                assessment_revision=1, source_record_refs=[dict(finding_id=finding['id'],revision=finding['revision'])],
                frozen_claim=dict(title=finding['title'],category='sqli',file_path='src/upload.php'))]
            value['canonical_findings'].append(dict(canonical_id='pending-identity',final_disposition='pending',
                current_claim_ref=dict(finding_id='pending-source',revision=1),assessment_revision=1,source_record_refs=[],
                frozen_claim=dict(title='待终审结论',category='sqli',file_path='src/pending.php')))
            api.json(route, value); return
        if path.startswith('/project-findings/') and path.endswith('/reports'):
            ledger_id = path.split('/')[2]
            if ledger_id == LEDGER_ID and hold_current[0]:
                held.append(route); return
            current = ledger_id == LEDGER_ID
            api.json(route, dict(current_available=current, items=[dict(run_id=COMPLETED_ID, canonical_id='canonical-identity',
                path=f'/runs/{COMPLETED_ID}/canonical-findings/canonical-identity/report',current=current,
                project_revision=1,assessment_revision=1,snapshot_name='冻结源码.zip')]))
            return
        if path.endswith('/report'):
            if failures[0]:
                failures[0] = False
                api.json(route, dict(detail=dict(code='report_not_ready', message='冻结报告暂未就绪，请重试。')),409); return
            query = parse_qs(url.query)
            downloads.append((path, query))
            route.fulfill(status=200,content_type='application/octet-stream',body='offline report',
                          headers={'Content-Disposition':'attachment; filename="frozen-report.txt"'})
            return
        api.handle(route)
    if args.screenshots:
        args.screenshots.mkdir(parents=True,exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.environ.get('CHROME_BIN'))
        page = browser.new_page(viewport=dict(width=1440,height=1000))
        page.on('pageerror',lambda exc: errors.append(str(exc)))
        page.route('**/api/**',handle)
        goto(page,args.base,f'#run/{COMPLETED_ID}')
        result = page.get_by_role('region',name='审计结果')
        expect(result).to_contain_text('已确认 1 条结论，可独立下载漏洞报告')
        expect(result).to_contain_text('另有 1 条待终审，不影响已确认部分交付')
        for theme in ('dark','light'):
            page.evaluate('theme=>document.documentElement.dataset.theme=theme',theme)
            for width in (1440,1024,768,390):
                page.set_viewport_size(dict(width=width,height=1000))
                result.scroll_into_view_if_needed()
                no_overflow(page,f'partial confirmed result {theme} {width}',checks)
                if args.screenshots:
                    result.screenshot(path=str(args.screenshots/f'partial-confirmed-{theme}-{width}.png'))
        page.set_viewport_size(dict(width=1440,height=1000))
        result.get_by_role('button',name='查看报告',exact=True).click()
        dialog = page.get_by_role('dialog',name='审计详情',exact=True)
        content = dialog.get_by_role('combobox',name='报告内容',exact=True)
        expect(content).to_have_value('audit')
        dialog.get_by_role('button',name='下载审计报告 zip',exact=True).click()
        expect(dialog.get_by_role('alert')).to_contain_text('冻结报告暂未就绪')
        with page.expect_download() as event:
            dialog.get_by_role('button',name='重试下载',exact=True).click()
        assert event.value.suggested_filename == 'frozen-report.txt'
        assert downloads[-1] == (f'/runs/{COMPLETED_ID}/report',dict(view=['audit'],format=['zip']))
        checks.passed('structured download errors remain readable and retry preserves the requested ZIP format and frozen view')
        for view,label in [('audit','审计报告'),('accepted','已确认漏洞报告'),('vulnerabilities','漏洞汇编'),('archive','归档原件')]:
            content.select_option(view)
            for fmt in ('markdown','json','zip'):
                with page.expect_download() as event:
                    dialog.get_by_role('button',name=f'下载{label} {fmt}',exact=True).click()
                assert event.value.suggested_filename == 'frozen-report.txt'
                assert downloads[-1] == (f'/runs/{COMPLETED_ID}/report',dict(view=[view],format=[fmt]))
        checks.passed('audit, vulnerability compilation and unchanged archive use explicit view/format contracts')
        dialog.get_by_role('tab',name='发现与验证',exact=True).click()
        expect(dialog.get_by_role('button',name='下载单漏洞报告 zip',exact=True)).to_have_count(0)
        expect(dialog.get_by_role('button',name='选择该任务历史冻结版本',exact=True)).to_be_visible()
        dialog.get_by_role('button',name='选择该任务历史冻结版本',exact=True).click()
        with page.expect_download():
            dialog.get_by_role('button',name='下载单漏洞报告 zip',exact=True).click()
        assert '/canonical-findings/canonical-identity/report' in downloads[-1][0]
        checks.passed('equal revision numbers on different source records never label a historical claim as current')
        close_dialog(page)
        with page.expect_download():
            result.get_by_role('button',name='下载已确认漏洞报告 markdown',exact=True).click()
        assert downloads[-1] == (f'/runs/{COMPLETED_ID}/report',dict(view=['accepted'],format=['markdown']))
        checks.passed('a partial run delivers accepted findings independently while keeping the other item pending')
        historical_source[0] = False
        page.reload()
        page.get_by_role('region',name='审计结果').get_by_role('button',name='查看报告',exact=True).click()
        dialog = page.get_by_role('dialog',name='审计详情',exact=True)
        dialog.get_by_role('tab',name='发现与验证',exact=True).click()
        expect(dialog.get_by_role('button',name='选择该任务历史冻结版本',exact=True)).to_have_count(0)
        expect(dialog.get_by_role('button',name='下载单漏洞报告 zip',exact=True)).to_be_visible()
        checks.passed('exact finding identity, conclusion revision and assessment revision enable current frozen downloads')
        close_dialog(page)
        goto(page,args.base,f'#findings/{LEDGER_ID}')
        reports = page.get_by_role('region',name='单漏洞报告下载',exact=True)
        expect(reports.get_by_role('combobox',name='报告来源版本',exact=True)).not_to_have_value('')
        with page.expect_download():
            reports.get_by_role('button',name='下载单漏洞报告 markdown',exact=True).click()
        goto(page,args.base,f'#findings/{STALE_LEDGER_ID}')
        reports = page.get_by_role('region',name='单漏洞报告下载',exact=True)
        expect(reports).to_contain_text('当前版本暂无冻结报告')
        expect(reports.get_by_role('button',name='下载单漏洞报告 markdown',exact=True)).to_have_count(0)
        reports.get_by_role('combobox',name='报告来源版本',exact=True).select_option(index=1)
        with page.expect_download():
            reports.get_by_role('button',name='下载单漏洞报告 json',exact=True).click()
        checks.passed('run finding resolves canonical identity; ledger defaults only to an exact current version and requires explicit historical choice')
        for theme in ('dark','light'):
            page.evaluate('theme=>document.documentElement.dataset.theme=theme',theme)
            for width in (1440,1024,768,390):
                page.set_viewport_size(dict(width=width,height=1000))
                reports.scroll_into_view_if_needed()
                no_overflow(page,f'report downloads {theme} {width}',checks)
                if args.screenshots:
                    page.screenshot(path=str(args.screenshots/f'report-{theme}-{width}.png'))
        hold_current[0] = True
        goto(page,args.base,f'#findings/{LEDGER_ID}')
        for _ in range(50):
            if held: break
            page.wait_for_timeout(20)
        assert held
        goto(page,args.base,f'#findings/{STALE_LEDGER_ID}')
        expect(page.get_by_role('region',name='单漏洞报告下载')).to_contain_text('当前版本暂无冻结报告')
        for route in held:
            try:
                api.json(route,dict(items=[],current_available=True))
            except Exception:
                pass  # old navigation cancelled its request
        expect(page.get_by_role('region',name='单漏洞报告下载').get_by_role('combobox',name='报告来源版本')).to_have_value('')
        checks.passed('rapid ledger navigation cancels a late source response and never selects a historical report implicitly')
        assert not errors,errors
        assert not api.unexpected,api.unexpected
        assert not any('readiness' in path or 'poc-gateway' in path for path in calls)
        browser.close()
    print(f'PASS {checks.count} report delivery checks; all API requests intercepted')


if __name__ == '__main__':
    main()
