#!/usr/bin/env python3
"""Exercise record deletion in a browser using in-memory APIs only.

uv run --with playwright python scripts/ui_records_smoke.py http://127.0.0.1:5173
No real library records or model calls are touched.
"""
from __future__ import annotations
import argparse
import copy
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from playwright.sync_api import expect, sync_playwright
from ui_fixtures import COMPLETED_ID, LEDGER_ID, NEWER_SNAPSHOT_ID, OTHER_PROJECT_ID, OTHER_SNAPSHOT_ID, PROJECT_ID, SNAPSHOT_ID, MockAPI, finding, run, snapshot, sources_api
from ui_smoke import Checks, goto, no_overflow, save


class RecordsAPI(MockAPI):
    def __init__(self):
        super().__init__()
        self.__dict__.update(sources_api().__dict__)
        self.mutations = []
        self.failures = {}
        self.hold_mutation = False
        self.pending_mutation = None
        self.hold_next_runs = False
        self.pending_read = None
        self.run_list_reads = 0
        self.prompts = [
            dict(id='builtin', label='内置规则', builtin=True, phase='baseline', text='内置正文', reason='', issues=[], created_at='2026-10-22T00:00:00+00:00'),
            dict(id='used', label='已引用草稿', builtin=False, phase='custom', text='历史正文', reason='', issues=[], created_at='2026-10-22T00:00:00+00:00'),
            dict(id='draft', label='待删除草稿', builtin=False, phase='custom', text='草稿正文', reason='', issues=[], created_at='2026-10-22T00:00:00+00:00'),
        ]
        self.runs[COMPLETED_ID]['prompt_id'] = 'used'
        for ident, status in [('record-running','running'), ('record-pending','pending'), ('record-paused','paused')]:
            self.add_run(ident, status)

    def add_run(self, ident, status, project=PROJECT_ID, source=SNAPSHOT_ID):
        value=run(ident, status)
        value.update(project_id=project, snapshot_id=source, snapshot_name=self.snapshot_records[source]['name'])
        self.runs[ident]=value
        self.findings[ident]=finding(ident)

    def delete_run_record(self, ident):
        value=self.runs.pop(ident)
        self.findings.pop(ident, None)
        return {'run_id':ident,'status_before':value['status'],'deleted':{'runs':1,'events':3,'findings':1,'verifications':1}}

    def deliver_mutation(self, route):
        path=urlsplit(route.request.url).path.removeprefix('/api')
        parts=path.strip('/').split('/')
        if self.failures.get(path):
            status=self.failures[path].pop(0)
            self.json(route, {'detail':'模拟删除冲突' if status==409 else '模拟删除失败'}, status)
        elif path=='/runs/cleanup':
            project=route.request.post_data_json.get('project_id')
            ids=[key for key,value in self.runs.items() if value['status'] not in {'pending','running'} and (not project or value.get('project_id')==project)]
            rows=[self.delete_run_record(ident) for ident in ids]
            self.json(route, {'deleted_runs':len(rows),'runs':rows})
        elif parts[0]=='runs':
            value=self.runs.get(parts[1])
            if value is None: self.json(route,{'detail':'Run does not exist'},404)
            elif value['status'] in {'running','pending'}: self.json(route,{'detail':'Run is running; cancel it before deleting'},409)
            else: self.json(route,self.delete_run_record(parts[1]))
        elif parts[0]=='snapshots':
            if any(value['snapshot_id']==parts[1] for value in self.runs.values()): self.json(route,{'detail':'Snapshot is referenced'},409)
            else:
                self.snapshot_records.pop(parts[1],None)
                route.fulfill(status=204,body='')
        else:
            self.prompts=[prompt for prompt in self.prompts if prompt['id']!=parts[1]]
            route.fulfill(status=204,body='')

    def handle(self, route):
        request=route.request
        path=urlsplit(request.url).path.removeprefix('/api')
        if request.method=='GET' and path=='/runs':
            self.run_list_reads += 1
            if self.hold_next_runs:
                self.hold_next_runs = False
                self.pending_read = (route, copy.deepcopy(list(reversed(list(self.runs.values())))))
            else: super().handle(route)
        elif request.method=='GET' and path=='/prompts':
            self.json(route, self.prompts)
        elif request.method=='DELETE' and path.startswith(('/runs/','/snapshots/','/prompts/')) or request.method=='POST' and path=='/runs/cleanup':
            self.mutations.append((request.method,path,request.post_data_json if request.method=='POST' else None))
            if self.hold_mutation: self.pending_mutation=route
            else: self.deliver_mutation(route)
        elif request.method=='GET' and path.startswith('/runs/') and len(path.split('/'))==3 and path.split('/')[-1] not in self.runs:
            self.json(route, {'detail':'Run does not exist'},404)
        else: super().handle(route)


def navigate(page, hash): page.evaluate('hash => { location.hash=hash; }', hash)
def dialog(page, title): return page.get_by_role('dialog',name=title,exact=True)
def confirm(page): return page.get_by_role('button',name='确认删除',exact=True)
def wait_pending(page, api):
    for _ in range(100):
        if api.pending_mutation is not None: return
        page.wait_for_timeout(30)
    raise AssertionError('Mutation never reached mock API')


def exercise(page, base, api, checks, screenshots):
    goto(page,base,'#run/record-running')
    expect(page.locator('.conversation-actions').get_by_role('button',name='删除审计记录',exact=True)).to_be_disabled()
    navigate(page,'#run/record-pending')
    expect(page.locator('.conversation-actions').get_by_role('button',name='删除审计记录',exact=True)).to_be_disabled()
    assert not api.mutations
    checks.passed('pending and running audits cannot be deleted from the conversation')

    navigate(page,f'#run/{COMPLETED_ID}')
    action=page.locator('.conversation-actions').get_by_role('button',name='删除审计记录',exact=True)
    action.click()
    expect(dialog(page,'删除审计记录')).to_contain_text('累计漏洞台账继续保留')
    page.get_by_role('button',name='取消',exact=True).click()
    assert not api.mutations
    expect(action).to_be_focused()
    checks.passed('canceling confirmation performs no deletion and restores focus')

    page.set_viewport_size({'width':390,'height':900})
    page.get_by_role('button',name='打开导航',exact=True).click()
    navigation=dialog(page,'审计工作空间')
    mobile_delete=navigation.locator('.history-record').filter(has=page.locator('.history-item[aria-current="page"]')).get_by_role('button',name=re.compile('删除审计'))
    mobile_delete.click()
    for _ in range(5):
        page.keyboard.press('Tab')
        assert page.evaluate('Boolean(document.activeElement.closest(".records-dialog"))')
    page.keyboard.press('Escape')
    expect(dialog(page,'删除审计记录')).to_have_count(0)
    expect(navigation).to_be_visible()
    expect(mobile_delete).to_be_focused()
    page.keyboard.press('Escape')
    expect(navigation).to_have_count(0)
    assert not api.mutations
    page.set_viewport_size({'width':1440,'height':900})
    checks.passed('mobile navigation keeps keyboard focus in the top confirmation and restores it on cancel')

    action.click()
    api.failures[f'/runs/{COMPLETED_ID}']=[409,503]
    confirm(page).click()
    expect(dialog(page,'删除审计记录').get_by_role('alert')).to_contain_text('状态已变化')
    assert COMPLETED_ID in api.runs
    confirm(page).click()
    expect(dialog(page,'删除审计记录').get_by_role('alert')).to_contain_text('模拟删除失败')
    checks.passed('conflicts and server failures retain the record and offer retry')
    api.hold_mutation=True
    confirm(page).evaluate('button => { button.click(); button.click(); }')
    wait_pending(page,api)
    assert len(api.mutations)==3
    expect(confirm(page)).to_be_disabled()
    page.keyboard.press('Escape')
    expect(dialog(page,'删除审计记录')).to_be_visible()
    route=api.pending_mutation
    api.pending_mutation=None
    api.hold_mutation=False
    api.deliver_mutation(route)
    expect(page).to_have_url(re.compile(f'#sources/{PROJECT_ID}\\?tab=tasks$'))
    expect(dialog(page,'删除审计记录')).to_have_count(0)
    expect(page.locator('.source-import-notice')).to_contain_text('已删除审计记录')
    expect(page.locator(f'a[href="#run/{COMPLETED_ID}"]')).to_have_count(0)
    assert LEDGER_ID in api.ledger_records
    checks.passed('delete submits once, leaves a busy dialog open, refreshes lists, and returns from the removed audit')

    navigate(page,'#run/record-paused')
    page.locator('.conversation-actions').get_by_role('button',name='删除审计记录',exact=True).click()
    expect(dialog(page,'删除审计记录')).to_contain_text('已暂停；删除后无法继续')
    confirm(page).click()
    expect(dialog(page,'删除审计记录')).to_have_count(0)
    assert 'record-paused' not in api.runs
    checks.passed('paused audits can be deleted with an explicit warning that continuation is lost')

    api.add_run('bulk-paused','paused')
    api.add_run('other-completed','completed',OTHER_PROJECT_ID,OTHER_SNAPSHOT_ID)
    navigate(page,f'#sources/{PROJECT_ID}')
    page.locator('.sources-head').get_by_role('button',name='清理审计记录',exact=True).click()
    expect(dialog(page,'清理审计记录')).to_contain_text('审计样例源码')
    expect(dialog(page,'清理审计记录')).to_contain_text('其中 1 次已暂停')
    page.get_by_role('button',name='确认清理',exact=True).click()
    expect(dialog(page,'清理审计记录')).to_have_count(0)
    assert api.mutations[-1][2]=={'project_id':PROJECT_ID}
    assert all(value['status'] in {'pending','running'} for value in api.runs.values() if value['project_id']==PROJECT_ID)
    assert 'other-completed' in api.runs
    checks.passed('project cleanup is scoped, includes paused audits, and skips active tasks')

    page.locator('.desktop-side').get_by_role('button',name='清理审计记录',exact=True).click()
    expect(dialog(page,'清理审计记录')).to_contain_text('全部源码项目')
    page.get_by_role('button',name='确认清理',exact=True).click()
    expect(dialog(page,'清理审计记录')).to_have_count(0)
    assert api.mutations[-1][2]=={} and 'other-completed' not in api.runs
    assert set(api.runs)=={'record-running','record-pending'}
    expect(page.locator('.desktop-side').get_by_role('button',name='清理审计记录',exact=True)).to_be_disabled()
    checks.passed('global cleanup uses the bulk API and disables itself when only active tasks remain')

    navigate(page,f'#sources/{PROJECT_ID}?tab=archives&snapshot={SNAPSHOT_ID}')
    expect(page.get_by_role('button',name='删除 ZIP 记录',exact=True)).to_be_disabled()
    expect(page.locator('.records-snapshot-delete')).to_contain_text('被 2 次审计引用')
    checks.passed('all audit references prevent ZIP deletion and explain how to remove them')

    navigate(page,f'#sources/{PROJECT_ID}?tab=archives&snapshot={NEWER_SNAPSHOT_ID}')
    page.get_by_role('button',name='删除 ZIP 记录',exact=True).click()
    confirm(page).click()
    expect(dialog(page,'删除 ZIP 记录')).to_have_count(0)
    expect(page.get_by_role('combobox',name='浏览 ZIP 快照',exact=True)).to_have_value(SNAPSHOT_ID)
    expect(page).to_have_url(re.compile(f'#sources/{PROJECT_ID}\\?tab=archives$'))
    assert NEWER_SNAPSHOT_ID not in api.snapshot_records
    checks.passed('deleting the selected newest ZIP falls back to the remaining ZIP and removes its stale URL selection')

    navigate(page,f'#sources/{OTHER_PROJECT_ID}?tab=archives')
    page.get_by_role('button',name='删除 ZIP 记录',exact=True).click()
    page.get_by_role('button',name='取消',exact=True).click()
    assert OTHER_SNAPSHOT_ID in api.snapshot_records
    page.get_by_role('button',name='删除 ZIP 记录',exact=True).click()
    api.failures[f'/snapshots/{OTHER_SNAPSHOT_ID}']=[409]
    confirm(page).click()
    expect(dialog(page,'删除 ZIP 记录').get_by_role('alert')).to_contain_text('仍被审计引用')
    confirm(page).click()
    expect(dialog(page,'删除 ZIP 记录')).to_have_count(0)
    expect(page.get_by_role('heading',name='没有可用的 ZIP 快照',exact=True)).to_be_visible()
    assert OTHER_SNAPSHOT_ID not in api.snapshot_records
    checks.passed('ZIP deletion handles new references, accepts 204, and clears the final snapshot selection')

    navigate(page,'#sources')
    empty_project=page.locator('.source-card').filter(has=page.locator(f'a.source-card-title[href="#sources/{OTHER_PROJECT_ID}?tab=tasks"]'))
    expect(empty_project.get_by_role('button',name='上传源码 ZIP',exact=True)).to_be_visible()
    expect(empty_project.get_by_role('link',name='开始审计',exact=True)).to_have_count(0)
    checks.passed('a project with no remaining ZIP offers an upload instead of a broken audit action')

    navigate(page,'#settings')
    page.get_by_role('button',name='提示词草稿',exact=True).click()
    expect(page.get_by_role('region',name='提示词 内置规则',exact=True).get_by_role('button',name='删除提示词草稿',exact=True)).to_be_disabled()
    # A still-existing active audit references this prompt.
    api.runs['record-running']['prompt_id']='used'
    page.get_by_role('button',name='刷新提示词',exact=True).click()
    page.wait_for_timeout(5200)
    expect(page.get_by_role('region',name='提示词 已引用草稿',exact=True).get_by_role('button',name='删除提示词草稿',exact=True)).to_be_disabled()
    draft=page.get_by_role('region',name='提示词 待删除草稿',exact=True)
    draft.get_by_role('button',name='删除提示词草稿',exact=True).click()
    expect(dialog(page,'删除提示词草稿')).to_contain_text('待删除草稿')
    confirm(page).click()
    expect(draft).to_have_count(0)
    assert api.mutations[-1][1]=='/prompts/draft'
    expect(page.locator('.source-import-notice')).to_contain_text('已删除提示词草稿')
    checks.passed('settings expose prompt management with built-in/reference guards and successful empty-body deletion')

    # Responsiveness and keyboard cancellation on a real confirmation dialog.
    for theme in ('dark','light'):
        page.set_viewport_size({'width':1440,'height':900})
        if page.locator('html').get_attribute('data-theme')!=theme:
            page.get_by_role('button',name=f"切换{'深' if theme=='dark' else '浅'}色主题",exact=True).click()
        api.add_run('visual-paused','paused')
        navigate(page,'#run/visual-paused')
        page.locator('.conversation-actions').get_by_role('button',name='删除审计记录',exact=True).click()
        for width in (1440,1024,768,390):
            page.set_viewport_size({'width':width,'height':900})
            no_overflow(page,f'delete confirmation {theme} {width}',checks)
            save(page,screenshots,f'delete-confirmation-{theme}-{width}')
        page.keyboard.press('Escape')
        expect(dialog(page,'删除审计记录')).to_have_count(0)
    checks.passed('confirmation remains usable across desktop/mobile themes and keyboard cancellation')


def exercise_races(page, base, api, checks):
    api.add_run('race-completed','completed')
    page.set_viewport_size({'width':1440,'height':900})
    goto(page,base,'#run/race-completed')
    expect(page.locator('.desktop-side .history-item[aria-current="page"]')).to_be_visible()
    api.hold_next_runs=True
    for _ in range(220):
        if api.pending_read: break
        page.wait_for_timeout(30)
    assert api.pending_read, 'Expected an in-flight list poll'
    page.locator('.conversation-actions').get_by_role('button',name='删除审计记录',exact=True).click()
    confirm(page).click()
    expect(dialog(page,'删除审计记录')).to_have_count(0)
    expect(page.locator('.source-import-notice')).to_contain_text('已删除审计记录')
    reads_before=api.run_list_reads
    held_route,stale_payload=api.pending_read
    api.pending_read=None
    api.json(held_route,stale_payload)
    for _ in range(100):
        if api.run_list_reads>reads_before: break
        page.wait_for_timeout(30)
    assert api.run_list_reads>reads_before, 'Deletion must queue a fresh read after the older poll'
    expect(page.locator('.source-run[href="#run/race-completed"]')).to_have_count(0)
    expect(page.locator('.desktop-side .history-item')).to_have_count(len(api.runs))
    checks.passed('a list poll started before deletion cannot restore the removed audit')

    api.add_run('background-delete','completed')
    goto(page,base,'#run/background-delete')
    page.locator('.conversation-actions').get_by_role('button',name='删除审计记录',exact=True).click()
    api.hold_mutation=True
    confirm(page).click()
    wait_pending(page,api)
    navigate(page,'#findings')
    held_route=api.pending_mutation
    api.pending_mutation=None
    api.hold_mutation=False
    api.deliver_mutation(held_route)
    expect(dialog(page,'删除审计记录')).to_have_count(0)
    expect(page).to_have_url(re.compile('#findings$'))
    assert 'background-delete' not in api.runs
    checks.passed('a completed background deletion preserves the page the user has navigated to')

    api.add_run('already-removed','completed')
    goto(page,base,'#run/already-removed')
    page.locator('.conversation-actions').get_by_role('button',name='删除审计记录',exact=True).click()
    api.delete_run_record('already-removed')
    confirm(page).click()
    expect(dialog(page,'删除审计记录')).to_have_count(0)
    expect(page.locator('.source-import-notice')).to_contain_text('记录已不存在')
    expect(page).to_have_url(re.compile(f'#sources/{PROJECT_ID}\\?tab=tasks$'))
    checks.passed('records deleted elsewhere return 404 and refresh the current page safely')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('frontend_url')
    parser.add_argument('--screenshots',type=Path)
    args=parser.parse_args()
    if args.screenshots: args.screenshots.mkdir(parents=True,exist_ok=True)
    checks=Checks()
    api=RecordsAPI()
    with sync_playwright() as pw:
        chrome=os.environ.get('CHROME_BIN')
        browser=pw.chromium.launch(**({'executable_path':chrome} if chrome else {}))
        page=browser.new_page(viewport={'width':1440,'height':900},locale='zh-CN',timezone_id='Asia/Shanghai')
        page.set_default_timeout(10000)
        errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.route('**/api/**',api.handle)
        try:
            exercise(page,args.frontend_url.rstrip('/'),api,checks,args.screenshots)
            exercise_races(page,args.frontend_url.rstrip('/'),api,checks)
            assert not errors,errors
            assert not api.unexpected,api.unexpected
            print(f'Passed {checks.count} record-management checks; all mutations used mocked APIs.',flush=True)
        except Exception:
            save(page,args.screenshots,'records-failure')
            raise
        finally: browser.close()

if __name__=='__main__': main()
