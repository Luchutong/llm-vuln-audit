#!/usr/bin/env python3
"""Budget checkpoint UI acceptance; all APIs are intercepted, no audit is started."""
import copy
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright, expect

from ui_fixtures import MockAPI, COMPLETED_ID
from ui_smoke import goto


def main():
    api=MockAPI();rid=COMPLETED_ID;item=api.runs[rid]
    item.update(status='paused',finished_at=None,run_limits=dict(responses=56,tools=3951,seconds=2810))
    item['task_spec'].update(orchestration_policy='host-queue-v1',workflow_policy='discovery_first')
    item['execution_summary']=dict(phase='paused',run_limits=item['run_limits'],
        run_usage=dict(responses=35,tools=34,seconds=1165.304),run_remaining=dict(responses=21,tools=3917,seconds=1644.696),
        active_executions=[],blocked_task_ids=[],poc=dict(mode='auto',available=True),final_summary_available=False,
        workflow=dict(version='host-queue-v1',stage='discovery',limits=dict(discovery=11,poc=22,review=23),
            used=dict(discovery=11,poc=22,review=2),remaining=dict(discovery=0,poc=0,review=21),
            transferred=0,review_reserved_seconds=500,budget_pause=dict(code='stage_budget_exhausted',stage='discovery',message='源码阶段预算不足',resumable=True)))
    posts=[];errors=[];resumes=[];expected=dict(responses=80,tools=600,seconds=2400)
    def handle(route):
        path=urlsplit(route.request.url).path
        if path==f'/api/runs/{rid}/resume':
            assert route.request.post_data_json=={}
            resumes.append(rid);item['status']='pending';api.json(route,copy.deepcopy(item))
        elif path==f'/api/runs/{rid}/budget':
            body=route.request.post_data_json;posts.append(body)
            assert set(body)=={'request_id','responses','tools','seconds','resume'}
            assert {k:body[k] for k in expected}==expected
            assert body['resume'] is True and len(body['request_id'])>=8
            if len(posts)==1:
                api.json(route,dict(detail='模拟尚未静止，请稍后重试'),409)
            else:
                assert posts[0]['request_id']==body['request_id']
                item['status']='pending';item['execution_summary']['workflow'].pop('budget_pause')
                api.json(route,copy.deepcopy(item))
        else:api.handle(route)
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path=os.environ.get('CHROME_BIN'),headless=True)
        page=browser.new_page(viewport=dict(width=1440,height=1000))
        page.add_init_script("Object.defineProperty(Crypto.prototype,'randomUUID',{value:undefined,configurable:true})")
        page.on('pageerror',lambda exc:errors.append(str(exc)));page.route('**/api/**',handle)
        goto(page,'http://127.0.0.1:5173',f'#run/{rid}')
        expect(page.get_by_role('button',name='继续运行',exact=True)).to_have_count(0)
        page.get_by_role('button',name='追加预算并继续',exact=True).click()
        dialog=page.get_by_role('dialog',name='追加预算并继续当前记录')
        expect(dialog.get_by_role('combobox')).to_have_count(0)
        expect(dialog.get_by_role('button',name=re.compile('继续一轮'))).to_have_attribute('aria-pressed','true')
        expect(dialog.get_by_role('spinbutton',name='新增模型请求')).not_to_be_visible()
        dialog.get_by_role('button',name=re.compile('小幅补充')).click()
        expect(dialog).to_contain_text('本次新增：64 次请求 · 512 次工具 · 30 分钟')
        dialog.locator('summary').click()
        expect(dialog.get_by_role('spinbutton',name='新增模型请求')).to_have_value('64')
        dialog.get_by_role('spinbutton',name='新增模型请求').fill('80')
        dialog.get_by_role('spinbutton',name='新增工具调用').fill('600')
        dialog.get_by_role('spinbutton',name='新增时长（分钟）').fill('40')
        expect(dialog).to_contain_text('已自定义')
        Path('.run').mkdir(exist_ok=True)
        page.screenshot(path='.run/budget-presets-desktop.png')
        dialog.get_by_role('button',name='追加并继续',exact=True).click()
        expect(dialog.get_by_role('alert')).to_contain_text('模拟尚未静止')
        expect(dialog.get_by_role('spinbutton',name='新增时长（分钟）')).to_have_value('40')
        dialog.get_by_role('button',name='追加并继续',exact=True).click()
        expect(dialog).to_have_count(0)
        assert page.url.endswith(f'#run/{rid}') and len(posts)==2
        assert not api.unexpected,api.unexpected
        assert not errors,errors
        item['status']='paused';item['execution_summary']['workflow']['budget_pause']=dict(code='stage_budget_exhausted',stage='discovery',message='源码阶段预算不足',resumable=True)
        page.close();page=browser.new_page(viewport=dict(width=390,height=844))
        page.route('**/api/**',handle);page.on('pageerror',lambda exc:errors.append(str(exc)))
        goto(page,'http://127.0.0.1:5173',f'#run/{rid}')
        page.get_by_role('button',name='追加预算并继续',exact=True).click()
        dialog=page.get_by_role('dialog',name='追加预算并继续当前记录')
        dialog.get_by_role('button',name=re.compile('深入补查')).click()
        expect(dialog).to_contain_text('本次新增：256 次请求 · 2048 次工具 · 90 分钟')
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path='.run/budget-presets-mobile.png')
        dialog.locator('summary').click()
        for label in ('新增模型请求','新增工具调用','新增时长（分钟）'):
            dialog.get_by_role('spinbutton',name=label).fill('0')
        expect(dialog.get_by_role('button',name='追加并继续',exact=True)).to_be_disabled()
        page.close();item['status']='paused'
        item['execution_summary']['workflow']['budget_pause']=dict(code='source_evidence_required',stage='discovery',message='仍有未完成源码取证',resumable=True)
        page=browser.new_page(viewport=dict(width=1440,height=1000))
        page.route('**/api/**',handle);page.on('pageerror',lambda exc:errors.append(str(exc)))
        goto(page,'http://127.0.0.1:5173',f'#run/{rid}')
        expect(page.get_by_text('源码补证受阻，剩余额度已保留',exact=True)).to_be_visible()
        page.get_by_role('button',name='使用剩余额度继续',exact=True).click()
        expect(page.get_by_role('button',name='暂停运行',exact=True)).to_be_visible()
        assert resumes==[rid] and len(posts)==2
        assert not errors,errors
        browser.close()
    print('PASS budget presets and evidence pause: tiers, tuning, minutes, retries, zero guard, desktop/mobile, resume without new grant, no real API')


if __name__=='__main__':main()
