#!/usr/bin/env python3
"""CVSS browser acceptance: only intercepted in-memory APIs, no real records/models."""
import argparse
import copy
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
from playwright.sync_api import expect,sync_playwright
from ui_fixtures import sources_api,LEDGER_ID,SOURCE_PATH,SNAPSHOT_ID,COMPLETED_ID
from ui_smoke import Checks,goto,no_overflow,save
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from audit.cvss31 import BASE
from audit.cvss_assessment import propose


class CvssAPI:
    def __init__(self):
        self.api=sources_api()
        self.puts=0;self.fail=None;self.conflict=False;self.pending=None;self.hold=False
        self.history=[]
        m={key:{'value':value,'rationale':f'{key}：根据已读取的源码判断攻击条件',
                'evidence':[{'path':SOURCE_PATH,'start_line':8,'end_line':12}]} for key,value in zip(BASE,'NLNNUHNN')}
        rating=propose(m,snapshot_id=SNAPSHOT_ID,run_id=COMPLETED_ID)
        self.row=self.api.ledger_records[LEDGER_ID]
        rating['cvss_assessment']['conclusion_revision']=self.row['revision']
        self.row.update(rating)
        self.original=copy.deepcopy(self.row)

    def deliver(self,route):
        body=route.request.post_data_json
        if self.fail:
            status=self.fail;self.fail=None;self.api.json(route,{'detail':'模拟评分服务失败'},status);return
        if self.conflict:
            self.conflict=False
            self.row['cvss_assessment']['assessment_revision']+=1
            self.api.json(route,{'detail':'结论或评分已更新，请刷新后比较并重新提交。'},409);return
        if body['expected_revision']!=self.row['revision'] or body['expected_assessment_revision']!=self.row['cvss_assessment']['assessment_revision']:
            self.api.json(route,{'detail':'评分版本冲突'},409);return
        try:
            rating=propose(body['metrics'],source='manual',strict=True,snapshot_id=SNAPSHOT_ID,run_id=COMPLETED_ID)
        except ValueError as exc:
            self.api.json(route,{'detail':str(exc)},422);return
        if route.request.method=='PUT':
            rating['cvss_assessment'].update(assessment_revision=body['expected_assessment_revision']+1,
                conclusion_revision=self.row['revision'],reason=body['reason'])
            self.row.update(rating)
            self.history.insert(0,{'id':len(self.history)+1,**copy.deepcopy(rating),'applicable':True,'source_run_available':True})
            self.api.json(route,self.row)
        else:self.api.json(route,rating)

    def handle(self,route):
        url=urlsplit(route.request.url);path=url.path.removeprefix('/api');method=route.request.method
        if path.endswith('/cvss-history'):
            offset=int(parse_qs(url.query).get('offset',['0'])[0])
            self.api.json(route,{'items':self.history[offset:offset+25],'total':len(self.history),'offset':offset,'limit':25})
        elif '/cvss' in path and method in {'POST','PUT'}:
            if method=='PUT':self.puts+=1
            if self.hold:self.pending=route
            else:self.deliver(route)
        elif path=='/project-findings' and 'cvss_status=' in url.query:
            params=parse_qs(url.query);status=params['cvss_status'][0]
            rows=[self.api.ledger_summary(row) for row in self.api.ledger_records.values() if (row.get('cvss_assessment') or {}).get('status')==status and (not params.get('severity') or row['severity']==params['severity'][0])]
            self.api.json(route,{'items':rows,'total':len(rows),'offset':0,'limit':25})
        else:self.api.handle(route)


def exercise(page,base,api,checks,shots):
    goto(page,base,f'#findings/{LEDGER_ID}')
    expect(page.get_by_role('heading',level=1)).to_be_visible()
    expect(page.locator('.ledger-detail-tags')).to_contain_text('高危 · 7.5')
    panel=page.get_by_role('region',name='CVSS 3.1 基础评分',exact=True)
    expect(panel).to_contain_text('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
    panel.get_by_role('button',name='查看八项指标与评分依据',exact=True).click()
    panel.locator('.cvss-metric').first.get_by_role('button',name=f'{SOURCE_PATH}:8-12',exact=True).click()
    expect(panel.get_by_role('region',name=re.compile('第 8 至 12 行源码'))).to_be_visible()
    assert api.api.source_requests[-1]['snapshot_id']==SNAPSHOT_ID
    checks.passed('automatic scores expose eight metric rationales and source from the actual ZIP')
    page.get_by_role('button',name='修订 CVSS 指标',exact=True).click()
    form=page.locator('.cvss-form')
    first=form.locator('fieldset').first
    first.get_by_role('button',name='添加源码引用',exact=True).click()
    first.get_by_label('AV 源码路径',exact=True).fill(SOURCE_PATH)
    first.get_by_label('AV 起始行',exact=True).fill('4')
    first.get_by_label('AV 结束行',exact=True).fill('5')
    first.get_by_role('button',name='添加引用',exact=True).click()
    expect(first.locator('.cvss-refs')).to_contain_text(f'{SOURCE_PATH}:4-5')
    first.get_by_role('checkbox').check()
    expect(first.locator('.cvss-refs')).to_have_count(0)
    first.get_by_label('AV 判断依据',exact=True).fill('人工核对：此入口通过网络访问，部署条件需另行确认')
    checks.passed('manual evidence can be added and assumptions explicitly clear unsupported source references')
    form.get_by_label('PR 指标取值',exact=True).select_option('H')
    form.get_by_label('CVSS 修订原因',exact=True).fill('确认入口要求后台高权限，调整权限指标')
    form.get_by_role('button',name='预览 CVSS 评分',exact=True).click()
    expect(form.get_by_role('status')).to_contain_text('中危 · 4.9')
    assert api.row['cvss']['base_score']==7.5 and api.puts==0
    checks.passed('preview computes on the server and leaves the canonical rating unchanged')
    api.fail=503
    form.get_by_role('button',name='保存项目评分',exact=True).click()
    expect(form.get_by_role('alert')).to_contain_text('模拟评分服务失败')
    expect(form.get_by_label('PR 指标取值',exact=True)).to_have_value('H')
    assert api.row['cvss']['base_score']==7.5
    form.get_by_role('button',name='预览 CVSS 评分',exact=True).click()
    expect(form.get_by_role('button',name='保存项目评分',exact=True)).to_be_enabled()
    api.conflict=True
    form.get_by_role('button',name='保存项目评分',exact=True).click()
    expect(form.get_by_role('alert')).to_contain_text('已更新')
    expect(form.get_by_label('PR 指标取值',exact=True)).to_have_value('H')
    expect(form.get_by_label('CVSS 修订原因',exact=True)).to_have_value('确认入口要求后台高权限，调整权限指标')
    form.get_by_role('button',name='刷新当前评分',exact=True).click()
    expect(page.locator('.cvss-panel').first).to_contain_text('评分第 2 版')
    form.get_by_role('button',name='基于当前版本重新预览',exact=True).click()
    form.get_by_role('button',name='预览 CVSS 评分',exact=True).click()
    expect(form.get_by_role('button',name='保存项目评分',exact=True)).to_be_enabled()
    checks.passed('503 and version conflicts preserve edits and require a new preview on the current version')
    prior=api.puts;api.hold=True
    form.get_by_role('button',name='保存项目评分',exact=True).evaluate('button=>{button.click();button.click();}')
    for _ in range(100):
        if api.pending:break
        page.wait_for_timeout(20)
    assert api.pending and api.puts==prior+1
    held=api.pending;api.pending=None;api.hold=False;api.deliver(held)
    expect(page.locator('.ledger-detail-tags')).to_contain_text('中危 · 4.9')
    assert api.row['verification_status']==api.original['verification_status']
    assert api.row['revision']==api.original['revision']
    page.get_by_role('button',name='评分修订历史',exact=True).click()
    expect(page.locator('.cvss-editor')).to_contain_text('修订原因：确认入口要求后台高权限')
    checks.passed('save submits once, updates the ledger, preserves POC/conclusion versions and retains rating history')
    for key in ('C','I','A'):form.get_by_label(f'{key} 指标取值',exact=True).select_option('N')
    form.get_by_role('button',name='预览 CVSS 评分',exact=True).click()
    expect(form.get_by_role('status')).to_contain_text('无基础影响 · 0.0')
    form.get_by_role('button',name='保存项目评分',exact=True).click()
    expect(page.locator('.ledger-detail-tags')).to_contain_text('无基础影响 · 0.0')
    page.evaluate("location.hash='#findings?severity=none&cvss_status=scored'")
    expect(page.locator('.ledger-table tbody tr')).to_have_count(1)
    expect(page.locator('.ledger-table')).to_contain_text('无基础影响 · 0.0')
    page.reload()
    expect(page.get_by_role('combobox',name='量化状态',exact=True)).to_have_value('scored')
    expect(page.get_by_role('combobox',name='严重性',exact=True)).to_have_value('none')
    checks.passed('zero scores remain findings and rating/severity filters restore on direct refresh')
    api.row.update(cvss=None,severity='unknown',legacy_severity='high',cvss_assessment={'status':'legacy_unrated','source':'legacy','assessment_revision':3,'conclusion_revision':api.row['revision'],'metric_details':{}})
    goto(page,base,f'#findings/{LEDGER_ID}')
    expect(page.locator('.ledger-detail-tags')).to_contain_text('历史等级 高危 · 未量化')
    api.row.update(cvss=None,severity='unknown',legacy_severity=None,cvss_assessment={'status':'needs_information','source':'auto','assessment_revision':4,'conclusion_revision':api.row['revision'],'metric_details':{}})
    page.reload()
    expect(page.locator('.ledger-detail-tags')).to_contain_text('待评分')
    checks.passed('legacy labels and new unknown metrics are explicit and never shown as numeric zero')
    page.get_by_role('button',name='修订 CVSS 指标',exact=True).click()
    for theme in ('dark','light'):
        page.set_viewport_size({'width':1440,'height':900})
        current=page.locator('html').get_attribute('data-theme')
        if current!=theme:page.get_by_role('button',name=f"切换{'深' if theme=='dark' else '浅'}色主题",exact=True).click()
        for width in (1440,1024,768,390):
            page.set_viewport_size({'width':width,'height':900})
            page.locator('.cvss-form fieldset').first.scroll_into_view_if_needed()
            no_overflow(page,f'CVSS editor {theme} {width}',checks)
            if shots:page.screenshot(path=str(shots/f'cvss-editor-{theme}-{width}.png'),animations='disabled')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('base');parser.add_argument('--screenshots',type=Path)
    args=parser.parse_args()
    if args.screenshots:args.screenshots.mkdir(parents=True,exist_ok=True)
    api=CvssAPI();checks=Checks()
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path=os.environ.get('CHROME_BIN'))
        page=browser.new_page(viewport={'width':1440,'height':900});page.set_default_timeout(10000)
        errors=[];page.on('pageerror',lambda exc:errors.append(str(exc)))
        page.route('**/api/**',api.handle)
        try:
            exercise(page,args.base.rstrip('/'),api,checks,args.screenshots)
            assert not errors,errors
            assert not api.api.unexpected,api.api.unexpected
            print(f'PASS {checks.count} CVSS browser checks; mock APIs only',flush=True)
        except Exception:
            save(page,args.screenshots,'cvss-failure');raise
        finally:browser.close()

if __name__=='__main__':main()
