#!/usr/bin/env python3
"""Two deliverables, shared report scope and download recovery (mock only)."""
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
        expect(result).to_contain_text('已确认 1 条结论，审计报告及证据包已保留')
        expect(result).to_contain_text('另有 1 条待终审，在同一报告中单独标注')
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
        expect(dialog.get_by_role('combobox',name='报告内容',exact=True)).to_have_count(0)
        dialog.get_by_role('button',name='下载审计报告 zip',exact=True).click()
        expect(dialog.get_by_role('alert')).to_contain_text('冻结报告暂未就绪')
        with page.expect_download() as event:
            dialog.get_by_role('button',name='重试下载',exact=True).click()
        assert event.value.suggested_filename == 'frozen-report.txt'
        assert downloads[-1] == (f'/runs/{COMPLETED_ID}/report',dict(view=['report'],format=['zip']))
        checks.passed('retry retains the requested evidence ZIP and the single frozen report view')
        for fmt in ('markdown','zip'):
            with page.expect_download():
                dialog.get_by_role('button',name=f'下载审计报告 {fmt}',exact=True).click()
            assert downloads[-1] == (f'/runs/{COMPLETED_ID}/report',dict(view=['report'],format=[fmt]))
        expect(dialog.get_by_role('button',name='下载审计报告 json',exact=True)).to_have_count(0)
        dialog.get_by_role('tab',name='发现与验证',exact=True).click()
        expect(dialog.get_by_role('button',name='下载单漏洞报告 zip',exact=True)).to_have_count(0)
        close_dialog(page)
        for fmt in ('markdown','zip'):
            with page.expect_download():
                result.get_by_role('button',name=f'下载审计报告 {fmt}',exact=True).click()
            assert downloads[-1] == (f'/runs/{COMPLETED_ID}/report',dict(view=['report'],format=[fmt]))
        checks.passed('compact and detailed results expose the same two artifacts including pending conclusions')
        for finding_id in (LEDGER_ID,STALE_LEDGER_ID):
            goto(page,args.base,f'#findings/{finding_id}')
            expect(page.get_by_role('region',name='单漏洞报告下载',exact=True)).to_have_count(0)
            no_overflow(page,'ledger report navigation',checks)
        assert not any(path.endswith('/reports') for path in calls)
        checks.passed('finding browsing no longer fetches or generates per-finding delivery variants')
        assert not errors,errors
        assert not api.unexpected,api.unexpected
        assert not any('readiness' in path or 'poc-gateway' in path for path in calls)
        browser.close()
    print(f'PASS {checks.count} report delivery checks; all API requests intercepted')


if __name__ == '__main__':
    main()
