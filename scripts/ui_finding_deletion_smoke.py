#!/usr/bin/env python3
"""Finding deletion browser acceptance; every API request is intercepted in memory.

Run against a static frontend preview. No real findings, runner or model are accessed.
"""
from __future__ import annotations

import argparse
import copy
import os
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright

from ui_fixtures import LEDGER_ID, OTHER_PROJECT_ID, PROJECT_ID, MockAPI, sources_api
from ui_smoke import Checks, goto, no_overflow, save


class FindingDeletionAPI(MockAPI):
    def __init__(self):
        super().__init__()
        self.__dict__.update(sources_api().__dict__)
        self.mutations = []
        self.failures = []
        self.hold = False
        self.pending = None

    def handle(self, route):
        url = urlsplit(route.request.url)
        path = url.path.removeprefix('/api')
        if route.request.method != 'DELETE' or not path.startswith('/project-findings'):
            return super().handle(route)
        self.mutations.append((path, parse_qs(url.query)))
        if self.hold:
            self.pending = route
        else:
            self.deliver(route)

    def deliver(self, route):
        if self.failures:
            code = self.failures.pop(0)
            return self.json(route, {'detail': '模拟清理服务失败'}, code)
        url = urlsplit(route.request.url)
        path = url.path.removeprefix('/api')
        ident = path.removeprefix('/project-findings/').strip('/') if path != '/project-findings' else None
        project_id = parse_qs(url.query).get('project_id', [None])[0]
        if ident:
            value = self.ledger_records.get(ident)
            if value is None:
                return self.json(route, {'detail': 'Project finding does not exist'}, 404)
            ids = [ident]
            project_id = value['project_id']
        else:
            ids = [key for key, value in self.ledger_records.items()
                   if not project_id or value['project_id'] == project_id]
        affected = list(dict.fromkeys(self.ledger_records[key]['project_id'] for key in ids))
        for key in ids:
            self.ledger_records.pop(key)
            self.ledger_verifications.pop(key, None)
        # The real storage tests cover linked and unlinked source-row cleanup. Here
        # exercise list refreshes and irreversible-mutation controls only.
        self.json(route, {'deleted_project_findings': len(ids), 'deleted_run_findings': len(ids),
                          'affected_project_ids': affected, 'deleted': {'project_findings': len(ids)}})


def navigate(page, hash):
    page.evaluate('hash => { location.hash = hash; }', hash)


def exercise(page, base, api, checks, screenshots):
    goto(page, base, '#findings')
    row = page.locator('tr').filter(has=page.locator(f'a[href^="#findings/{LEDGER_ID}?"]'))
    row.get_by_role('button', name='删除漏洞 上传路径可绕过目录边界', exact=True).click()
    dialog = page.get_by_role('dialog', name='删除漏洞', exact=True)
    expect(dialog).to_contain_text('上传路径可绕过目录边界')
    page.get_by_role('button', name='取消', exact=True).click()
    assert not api.mutations and LEDGER_ID in api.ledger_records
    checks.passed('canceling single deletion leaves the ledger untouched')

    row.get_by_role('button', name='删除漏洞 上传路径可绕过目录边界', exact=True).click()
    api.failures = [409, 503]
    page.get_by_role('button', name='确认删除', exact=True).click()
    expect(dialog.get_by_role('alert')).to_be_visible()
    assert LEDGER_ID in api.ledger_records
    page.get_by_role('button', name='确认删除', exact=True).click()
    expect(dialog.get_by_role('alert')).to_contain_text('模拟清理服务失败')
    assert LEDGER_ID in api.ledger_records
    api.hold = True
    before = len(api.mutations)
    page.get_by_role('button', name='确认删除', exact=True).evaluate('button => { button.click(); button.click(); }')
    for _ in range(100):
        if api.pending:
            break
        page.wait_for_timeout(20)
    assert api.pending and len(api.mutations) == before + 1
    expect(page.get_by_role('button', name='确认删除', exact=True)).to_be_disabled()
    page.keyboard.press('Escape')
    expect(dialog).to_be_visible()
    api.hold = False
    pending, api.pending = api.pending, None
    api.deliver(pending)
    expect(dialog).to_have_count(0)
    expect(row).to_have_count(0)
    assert LEDGER_ID not in api.ledger_records
    checks.passed('conflicts and failures preserve data; a busy confirmation submits only once')

    detail_id = 'ledger-page-00'
    navigate(page, f'#findings/{detail_id}')
    expect(page.get_by_role('heading', name='待核查数据流 00', exact=True)).to_be_visible()
    page.get_by_role('button', name='删除漏洞', exact=True).click()
    page.get_by_role('button', name='确认删除', exact=True).click()
    expect(page).to_have_url(re.compile(f'#sources/{PROJECT_ID}\\?tab=findings$'))
    assert detail_id not in api.ledger_records
    checks.passed('detail deletion returns to the owning source project')

    # A deletion in another tab must also discard the cached detail on refresh.
    external_id = 'ledger-page-01'
    navigate(page, f'#findings/{external_id}')
    expect(page.get_by_role('heading', name='待核查数据流 01', exact=True)).to_be_visible()
    api.ledger_records.pop(external_id)
    page.get_by_role('button', name='刷新漏洞详情', exact=True).click()
    expect(page.get_by_role('heading', name='无法读取漏洞详情', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='待核查数据流 01', exact=True)).to_have_count(0)
    checks.passed('a deleted detail is discarded on 404 instead of retaining a cached conclusion')

    # An active run in a different project must not block this project's cleanup.
    active = copy.deepcopy(next(iter(api.runs.values())))
    active.update(id='other-active', project_id=OTHER_PROJECT_ID, status='running')
    api.runs[active['id']] = active
    navigate(page, '#findings?project=' + PROJECT_ID + '&q=does-not-match')
    # Use the public select to avoid depending on the URL filter spelling.
    page.get_by_role('combobox', name='所属源码包', exact=True).select_option(PROJECT_ID)
    page.get_by_role('button', name='清空本项目漏洞', exact=True).click()
    dialog = page.get_by_role('dialog', name='清空本项目漏洞', exact=True)
    expect(dialog).to_contain_text('审计样例源码')
    expect(dialog).to_contain_text('筛选')
    snapshots_before, runs_before = set(api.snapshot_records), set(api.runs)
    page.get_by_role('button', name='确认清空漏洞', exact=True).click()
    expect(dialog).to_have_count(0)
    assert api.mutations[-1] == ('/project-findings', {'project_id': [PROJECT_ID]})
    assert not any(value['project_id'] == PROJECT_ID for value in api.ledger_records.values())
    assert 'ledger-other-project' in api.ledger_records
    assert snapshots_before == set(api.snapshot_records) and runs_before == set(api.runs)
    checks.passed('project cleanup includes hidden/filtered findings and preserves other projects, ZIPs and runs')

    api.runs.pop('other-active')
    goto(page, base, '#findings')
    page.get_by_role('button', name='清空全部漏洞', exact=True).click()
    dialog = page.get_by_role('dialog', name='清空全部漏洞', exact=True)
    expect(dialog).to_contain_text('全部源码项目')
    for theme in ('dark', 'light'):
        page.evaluate("theme => document.documentElement.setAttribute('data-theme', theme)", theme)
        for width in (1440, 1024, 768, 390):
            page.set_viewport_size({'width': width, 'height': 900})
            no_overflow(page, f'finding cleanup {theme} {width}px', checks)
            save(page, screenshots, f'finding-cleanup-{theme}-{width}')
    page.get_by_role('button', name='确认清空漏洞', exact=True).click()
    expect(dialog).to_have_count(0)
    expect(page.get_by_role('heading', name='还没有漏洞发现', exact=True)).to_be_visible()
    assert not api.ledger_records and api.mutations[-1] == ('/project-findings', {})
    assert api.runs and api.snapshot_records
    checks.passed('global cleanup resets findings and keeps source archives and audit history')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('frontend_url')
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    api, checks = FindingDeletionAPI(), Checks()
    with sync_playwright() as pw:
        chrome = os.environ.get('CHROME_BIN')
        browser = pw.chromium.launch(**({'executable_path': chrome} if chrome else {}))
        page = browser.new_page(viewport={'width': 1440, 'height': 900}, locale='zh-CN')
        page.set_default_timeout(10000)
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.route('**/api/**', api.handle)
        try:
            exercise(page, args.frontend_url.rstrip('/'), api, checks, args.screenshots)
            assert not api.unexpected, api.unexpected
            assert not errors, errors
            print(f'Passed {checks.count} finding-deletion browser checks; all APIs were mocked.')
        except Exception:
            save(page, args.screenshots, 'finding-deletion-failure')
            raise
        finally:
            browser.close()


if __name__ == '__main__':
    main()
