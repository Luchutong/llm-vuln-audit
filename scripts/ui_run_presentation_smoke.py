#!/usr/bin/env python3
"""Run conversation acceptance. All /api requests are fulfilled locally; no audit/runner calls."""
import argparse
import os
from collections import Counter
from pathlib import Path
from playwright.sync_api import expect, sync_playwright
from ui_fixtures import ACTIVITY_ID, event, run, finding, sources_api
from ui_smoke import Checks, goto, no_overflow, close_dialog, install_activity_stream, open_more
from ui_execution_smoke import phase_report


def execution(stage='discovery'):
    return dict(phase='task_execute', run_usage=dict(responses=12, tools=24, seconds=760),
        run_limits=dict(responses=256, tools=2048, seconds=1800), run_remaining=dict(responses=244, tools=2024, seconds=1040),
        active_executions=[], blocked_task_ids=[], poc=dict(mode='off'),
        workflow=dict(version='host-queue-v1', stage=stage), verification=dict(reviewed=3))


def facts():
    return dict(schema_version='final-review/v1', provenance=dict(immutable=True),
        counts=dict(raw_records=16, valid_records=16, canonical=6, accepted=3, pending=2, contested=1, withdrawn=0),
        run_outcome=dict(status='inconclusive', audit_complete=False),
        quality_result=dict(report_kind='partial', publishability='releasable_partial', failed_checks=[]),
        coverage=dict(files=dict(total=10, read=6, reviewed=4, skipped=0, pending=4, complete=False),
            directions=dict(total=5, resolved=3, skipped=0, unsettled=2, complete=False),
            verification=dict(total=6, verified=4, rejected=1, uncertain=1, pending=0)),
        canonical_findings=[], action_items=[])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base'); parser.add_argument('--screenshots', type=Path)
    args=parser.parse_args(); api=sources_api(); checks=Checks(); reads=Counter(); pending=[]; observed=[]
    modes={}
    api.runs[ACTIVITY_ID]=run(ACTIVITY_ID, 'running')
    live=api.runs[ACTIVITY_ID]; live.update(execution_summary=execution(), poc_mode='off')
    live['task_spec']['objective']='审计商城的上传、认证与数据访问路径，核对输入到危险操作之间的证据。' * 6
    api.findings[ACTIVITY_ID]=finding(ACTIVITY_ID)
    api.detail_overrides[ACTIVITY_ID]=dict(tasks=[dict(id='task-upload', title='核对上传路径与部署约束', state='running'),dict(id='task-auth',title='检查登录后的权限边界',state='running')])
    api.event_overrides[ACTIVITY_ID]=[event(ACTIVITY_ID,1,'workflow_stage_changed',dict(stage='discovery'))]
    context=dict(role='worker', task_id='task-upload', agent_invocation_id='ui-local', request_index=1)
    for index in range(4):
        api.event_overrides[ACTIVITY_ID].extend([event(ACTIVITY_ID,2+index*2,'tool_call',dict(context,tool='read_source',call_id=f'c{index}',args=dict(path='src/upload.php',start=1,end=10))),event(ACTIVITY_ID,3+index*2,'tool_result',dict(context,tool='read_source',call_id=f'c{index}',status='ok'))])
    api.event_overrides[ACTIVITY_ID].append(event(ACTIVITY_ID,10,'task_assessment',dict(context,summary='已定位路径拼接风险，正在核对可触发条件。')))
    for name in ('complete','partial','legacy','read-error','missing-fields','slow','fresh','cancelled','failed','interrupted','unreachable'):
        rid=f'ui-{name}'; item=run(rid,'completed' if name in ('complete','partial','legacy','read-error','missing-fields','slow','fresh') else name)
        item.update(execution_summary=execution('review'))
        item['execution_summary']['phase']='ended'
        api.runs[rid]=item; api.findings[rid]=finding(rid)
    api.runs['ui-legacy']['final_summary']=phase_report()
    def handle(route):
        path=route.request.url.split('/api/',1)[1].split('?',1)[0]; observed.append(path)
        if path.endswith('/final-review'):
            rid=path.split('/')[1]; reads[rid]+=1
            if rid=='ui-slow': pending.append(route); return
            if rid=='ui-legacy': api.json(route,dict(detail='No frozen facts'),404); return
            if rid=='ui-read-error' and reads[rid]==1: api.json(route,dict(detail='离线模拟读取失败'),503); return
            value=facts()
            if rid=='ui-complete':
                value['counts'].update(accepted=6,pending=0,contested=0)
                value['run_outcome']['audit_complete']=True
                value['quality_result'].update(report_kind='final',publishability='releasable_final')
            if rid=='ui-missing-fields': value=dict(schema_version='final-review/v1',provenance=dict(immutable=True))
            api.json(route,value); return
        api.handle(route)
    if args.screenshots: args.screenshots.mkdir(parents=True,exist_ok=True)
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path=os.environ.get('CHROME_BIN'))
        page=browser.new_page(viewport=dict(width=1440,height=1000)); page.set_default_timeout(10000)
        errors=[]; page.on('pageerror',lambda error:errors.append(str(error)))
        page.route('**/api/**',handle); install_activity_stream(page)
        goto(page,args.base,f'#run/{ACTIVITY_ID}')
        compact=page.get_by_role('region',name='当前执行摘要',exact=True)
        expect(compact).to_contain_text('核对上传路径与部署约束'); expect(compact).to_contain_text('已运行 12 分钟')
        expect(page.locator('.activity-tool')).to_have_count(0)
        expect(page.locator('.activity-process-group')).to_contain_text('已读取 1 个文件 · 4 次操作')
        expect(page.get_by_role('region',name='执行预算与验证策略')).to_have_count(0)
        compact.get_by_role('button',name='另有 1 项',exact=True).click(); expect(compact).to_contain_text('检查登录后的权限边界')
        page.locator('.chat-scroll').evaluate('node=>node.scrollTop=0')
        page.get_by_role('button',name='展开任务目标',exact=True).click()
        expand=page.get_by_role('button',name='收起任务目标',exact=True); expand.focus()
        position=page.locator('.chat-scroll').evaluate('node=>node.scrollTop')
        def update():
            ident=max(row['id'] for row in api.event_overrides[ACTIVITY_ID])+1
            row=event(ACTIVITY_ID,ident,'audit_progress',dict(context,message='继续核对本方向的证据。'))
            api.event_overrides[ACTIVITY_ID].append(row)
            assert page.evaluate('rows=>window.__emitAuditActivity(rows)',[row])==1
        update(); page.wait_for_timeout(1200); expect(expand).to_be_focused()
        assert abs(page.locator('.chat-scroll').evaluate('node=>node.scrollTop')-position)<3
        checks.passed('compact stage/current tasks; ordinary actions fold; task expansion keeps focus and reading position')
        expand.click()
        compact.get_by_role('button', name='另有 1 项', exact=True).click()
        if page.get_by_role('button', name='有新活动', exact=True).count():
            page.get_by_role('button', name='有新活动', exact=True).click()
        page.evaluate('document.activeElement?.blur()')
        for theme in ('dark','light'):
            page.evaluate('theme=>document.documentElement.dataset.theme=theme',theme)
            for width in (1440,1024,768,390):
                page.set_viewport_size(dict(width=width,height=1000)); compact.scroll_into_view_if_needed()
                no_overflow(page,f'compact running {theme} {width}',checks)
                if args.screenshots: page.screenshot(path=str(args.screenshots/f'running-{theme}-{width}.png'))
        page.set_viewport_size(dict(width=1440,height=1000))
        live['execution_summary'].update(phase='poc_execute',poc=dict(mode='auto',available=True),poc_statistics=dict(model=dict(waiting_seconds=12),experiments=dict(observations=0),conclusion=dict(published=0)))
        live['execution_summary']['workflow']['stage']='poc'; update()
        expect(compact).to_contain_text('等待模型响应')
        live['execution_summary']['poc_statistics']['experiments']['observations']=2; update()
        expect(compact).to_contain_text('已有实验观测，尚未发布')
        live['execution_summary']['poc']=dict(mode='auto',available=False,reason='runner_unconfigured'); update()
        expect(compact).to_contain_text('尚未配置自动验证环境')
        live.update(status='paused'); update(); expect(page.get_by_role('button',name='继续运行',exact=True)).to_be_disabled()
        expect(compact).to_contain_text('正在暂停')
        live['execution_summary']['phase']='paused'; update(); expect(page.get_by_role('button',name='继续运行',exact=True)).to_be_enabled()
        expect(page.locator('.result-card')).to_have_count(0)
        checks.passed('POC waiting/observations/unavailable and pause-settling remain distinct; paused is not a terminal result')
        for name in ('complete','partial','cancelled','failed','interrupted','unreachable'):
            goto(page,args.base,f'#run/ui-{name}'); result=page.get_by_role('region',name='审计结果',exact=True)
            expect(result).to_contain_text('冻结终审结果'); expect(result).to_contain_text('规范结论')
            if name=='complete': expect(result).to_contain_text('目标已达成')
            else: expect(result).to_contain_text('存疑或排除')
            if name=='partial': expect(page.locator('.conversation-meta')).to_contain_text('审计未完成')
        goto(page,args.base,'#run/ui-partial'); result=page.get_by_role('region',name='审计结果',exact=True)
        result.get_by_role('button',name='查看报告',exact=True).click()
        dialog=page.get_by_role('dialog',name='审计详情',exact=True)
        expect(dialog.get_by_role('region',name='终审事实包')).to_contain_text('规范结论：6')
        expect(dialog.get_by_role('region',name='终审事实包')).to_contain_text('终审接受：3')
        assert reads['ui-partial']==1,'report duplicated immutable final-review request'
        for label,fmt in [('Markdown','markdown'),('JSON','json'),('证据包','zip')]:
            button = dialog.locator('.drawer-downloads').get_by_role('button', name=f'下载审计报告 {fmt}', exact=True)
            expect(button).to_be_visible()
            with page.expect_download() as download:
                button.click()
            assert download.value.suggested_filename == 'offline-report.txt'
        close_dialog(page)
        page.get_by_role('button',name='审计详情',exact=True).click()
        expect(page.get_by_role('dialog',name='审计详情')).to_contain_text('ZIP SHA-256')
        expect(page.get_by_role('dialog',name='审计详情')).to_contain_text(api.snapshot_records[api.runs['ui-partial']['snapshot_id']]['archive_sha256'])
        close_dialog(page)
        for theme in ('dark','light'):
            page.evaluate('theme=>document.documentElement.dataset.theme=theme',theme)
            for width in (1440,1024,768,390):
                page.set_viewport_size(dict(width=width,height=1000)); result.scroll_into_view_if_needed()
                no_overflow(page,f'compact result {theme} {width}',checks)
                if args.screenshots: page.screenshot(path=str(args.screenshots/f'result-{theme}-{width}.png'))
        checks.passed('terminal states, canonical/accepted/pending counts and shared report cache agree; downloads retained')
        goto(page,args.base,'#run/ui-legacy'); result=page.get_by_role('region',name='审计结果',exact=True)
        expect(result).to_contain_text('宿主阶段结果'); expect(result).to_contain_text('终审接受数量暂无数据')
        goto(page,args.base,'#run/ui-read-error'); result=page.get_by_role('region',name='审计结果',exact=True)
        expect(result).to_contain_text('终审读取失败'); expect(result.locator('.run-result-counts')).to_have_count(0)
        result.get_by_role('button',name='重试终审读取',exact=True).click(); expect(result).to_contain_text('冻结终审结果'); assert reads['ui-read-error']==2
        goto(page,args.base,'#run/ui-missing-fields'); result=page.get_by_role('region',name='审计结果',exact=True)
        expect(result).to_contain_text('暂无数据'); expect(result.locator('.run-result-counts')).not_to_contain_text('0')
        result.get_by_role('button',name='查看报告',exact=True).click()
        expect(page.get_by_role('dialog')).to_contain_text('部分字段暂无数据')
        expect(page.get_by_role('dialog')).not_to_contain_text('NaN')
        close_dialog(page)
        checks.passed('legacy fallback never guesses accepted counts; request errors retry; missing values stay unknown')
        page.set_viewport_size(dict(width=1440,height=1000)); goto(page,args.base,'#run/ui-slow')
        expect(page.get_by_role('region',name='审计结果')).to_contain_text('正在读取终审结果')
        page.evaluate("location.hash='#run/ui-fresh'"); expect(page.get_by_role('region',name='审计结果')).to_contain_text('冻结终审结果')
        for route in pending:
            try: api.json(route,dict(facts(),counts=dict(canonical=999,accepted=999,pending=0)))
            except Exception: pass # Browser is allowed to abort the obsolete intercepted read.
        expect(page.get_by_role('region',name='审计结果')).not_to_contain_text('999')
        open_more(page); expect(page.get_by_role('button',name='基于此任务新建',exact=True)).to_be_visible()
        page.locator('.run-more > summary').focus(); page.keyboard.press('Escape'); expect(page.locator('.run-more > summary')).to_be_focused()
        assert not errors,errors
        assert not any('/poc/' in path or path.startswith('poc/') for path in observed),observed
        checks.passed('fast navigation cancels stale terminal facts; more menu keeps keyboard focus; no POC request issued')
        browser.close()
    print(f'PASS {checks.count} run presentation checks; mocked API only')

if __name__=='__main__': main()
