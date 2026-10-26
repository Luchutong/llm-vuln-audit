#!/usr/bin/env python3
"""Offline Lab30 complete-audit comparison acceptance; every API is mocked.

Usage: ui_prompt_comparison_v2_smoke.py http://127.0.0.1:<static-dist-port>
Never starts an audit, contacts a model, reads user data or changes the live Lab30.
"""
from __future__ import annotations

import argparse
import copy
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright
from ui_fixtures import STAMP, sources_api
from ui_smoke import Checks, goto, no_overflow

CLASSES = ['auth_bypass','code_execution','command_injection','csrf','idor','info_disclosure',
           'insecure_deserialization','lfi','mass_assignment','open_redirect','path_traversal',
           'price_manipulation','race_condition','rfi','session_fixation','sqli','ssrf','weak_crypto',
           'weak_type_comparison','xss_r','xss_s','xxe']
IDS = ['worker-w0-v1','worker-w1-v1','worker-w2-v1']


def metric(value, sd=.03, n=3):
    return dict(mean=value,sample_std=sd if n>1 else None,n=n,values=[])


def full_record():
    variants=[dict(id=p,label=['W0 基础审计','W1 证据与防护','W2 跨文件与业务前提'][i],
                   text='共享策略\n'+['基础核对','增加证据与防护核对','增加跨文件业务前提'][i],
                   sha256=str(i)*64,reason=['基础能力','检查既有防护','核对身份与业务状态'][i],
                   parent_id=IDS[i-1] if i else None,kind='worker_strategy',contract_version='worker-strategy-v1')
              for i,p in enumerate(IDS)]
    trials=[]
    for round_index in range(1,4):
        for i,prompt_id in enumerate(IDS):
            tp=[12,18,9][i]
            score=dict(TP=tp,D=1,U=2,FN=30-tp,FP=3,precision=tp/(tp+3),recall=tp/30,f1=2*tp/(tp+33),
                       matches=[dict(finding_id='finding-one',truth_id='01')],duplicates=[],unmatched=[],diagnostics=[])
            trials.append(dict(id=f'trial-{round_index}-{i}',round_index=round_index,prompt_id=prompt_id,
                               status='completed',evaluation_status='valid',stop_reason=dict(code='run_budget_exhausted') if i==2 else 'audit_complete',
                               read_coverage=dict(read_files=20,total_files=69,read_lines=500,total_lines=2000,file_ratio=20/69,line_ratio=.25),
                               duration_seconds=60,score=score,usage=dict(requests=20,tool_calls=80,total_tokens=12000),
                               attempts=[dict(id=f'attempt-{round_index}-{i}',attempt_no=1,status='completed',evaluation_status='valid')]))
    summaries=[]
    for i,p in enumerate(IDS):
        score=trials[i]['score']
        metrics={key:metric(score[key]) for key in ['TP','D','U','FN','precision','recall','f1']}
        metrics.update({key:metric(value) for key,value in dict(requests=20,tool_calls=80,input_tokens=10000,output_tokens=2000,total_tokens=12000,duration_seconds=60,tokens_per_tp=1000,cvss_mae=1.2,cvss_coverage=.9,cvss_severity_agreement=.8).items()})
        delta=[0,.1,-.12][i]
        paired=metric(delta)
        paired['values']=[dict(round_index=r,trial_id=f'trial-{r}-{i}',baseline_trial_id=f'trial-{r}-0',value=delta) for r in range(1,4)]
        summaries.append(dict(id=p,label=variants[i]['label'],metrics=metrics,paired_deltas=dict(f1=paired,recall=paired),valid_trials=3))
    truth_matrix=[]
    for n in range(1,31):
        truth_matrix.append(dict(id=f'{n:02}',title=f'测试真值 {n:02}',**{'class':CLASSES[(n-1)%22]},variants={p:dict(hits=3 if n<=[12,18,9][i] else 0,total=3,rounds=[dict(round_index=r,trial_id=f'trial-{r}-{i}',detected=n<=[12,18,9][i],finding_id='finding-one' if n==1 else None) for r in range(1,4)]) for i,p in enumerate(IDS)}))
    summary=dict(complete_rounds=[1,2,3],complete_round_count=3,repeats=3,preliminary=False,baseline_prompt_id=IDS[0],variants=summaries,truth_matrix=truth_matrix,
                 class_coverage=[dict(**{'class':category},total=3,variants={p:dict(detected=2,total=3,recall=2/3) for p in IDS}) for category in CLASSES],
                 cvss_common_rounds=[],actual_total_usage=dict(requests=dict(known_total=180,known_attempts=9,attempts=9),total_tokens=dict(known_total=108000,known_attempts=9,attempts=9)))
    return dict(id='full-comparison',protocol='lab30-full-v2',status='completed',created_at=STAMP,finished_at=STAMP,error='',
                manifest=dict(variants=variants,baseline_prompt_id=IDS[0],repeats=3,model=dict(model='offline-fixture-model',base_url='http://model.invalid'),
                              budgets=dict(responses=24,tools=96,seconds=720),run_limits=dict(responses=256,tools=2048,seconds=720),hashes=dict(source='a'*64),experiment_wall_seconds=7200),
                trials=trials,summary=summary)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base')
    parser.add_argument('--screenshots',type=Path)
    args=parser.parse_args()
    fixture=sources_api()
    full=full_record()
    prompts=[dict(v,builtin=True,phase='worker',issues=[],created_at=STAMP,used_by_runs=0,used_by_experiments=1) for v in full['manifest']['variants']]
    prompts.append(dict(id='used-custom',kind='worker_strategy',contract_version='worker-strategy-v1',label='实验已引用策略',text='冻结自定义策略',reason='',phase='custom',issues=[],created_at=STAMP,builtin=False,used_by_runs=0,used_by_experiments=1))
    legacy=dict(id='old-comparison',status='completed',created_at=STAMP,finished_at=STAMP,variants=['P0-basic'],units_limit=6,scenario=None,model='old-model',rows=[dict(variant='P0-basic',score=dict(TP=1,FP=1,FN=29,precision=.5,recall=1/30,f1=2/32))],progress={},error='')
    zero=copy.deepcopy(full)
    zero.update(id='zero-report')
    base=zero['summary']['variants'][0]['metrics']
    for key in ('TP','D','U','recall','f1'):
        base[key]=metric(0,0)
    base['FN']=metric(30,0)
    base['precision']=metric(None,None,0)
    base['total_tokens']=metric(None,None,0)
    for trial in zero['trials']:
        if trial['prompt_id']==IDS[0]:
            trial['score'].update(TP=0,D=0,U=0,FN=30,precision=None,recall=0,f1=0)
    invalid=copy.deepcopy(full)
    invalid.update(id='incomplete-comparison')
    invalid['summary'].update(complete_rounds=[1,2],complete_round_count=2,preliminary=True)
    bad=invalid['trials'][-1]
    bad.update(status='failed',evaluation_status='invalid',can_retry=True,stop_reason='model_unavailable',score=None)
    bad['attempts'][0].update(status='failed',evaluation_status='invalid')
    history=[full,zero,invalid,legacy]
    calls=[]
    writes=[]
    fail_detail=[False]
    fail_source=[False]
    held=[]
    held_catalog=[]
    hold_catalog=[False]
    live_events=[dict(id=n,run_id='isolated-live-run',kind='live_event',actor_role='worker',payload=dict(message=f'live-event-{n}'),created_at=STAMP) for n in range(1,151)]
    event_reads=[]
    def fresh_stamp():
        return datetime.now(timezone.utc).isoformat()
    def make_running(created):
        current_time=datetime.now(timezone.utc)
        batch=dict(id='initial-batch',kind='initial',started_at=current_time.isoformat(),deadline_at=(current_time+timedelta(seconds=7200)).isoformat(),remaining_seconds=7200)
        for item in created['trials']:
            item.update(status='pending',evaluation_status='pending',score=None,attempts=[],usage={},run_id=None)
        first=created['trials'][0]
        first.update(status='running',run_id='isolated-live-run',attempts=[dict(id='live-attempt',attempt_no=1,status='running',evaluation_status='pending',run_id='isolated-live-run')])
        created['summary'].update(complete_rounds=[],complete_round_count=0,preliminary=True)
        for row in created['summary']['variants']:
            row.update(valid_trials=0)
            for value in row['metrics'].values():
                value.update(mean=None,sample_std=None,n=0,values=[])
            for value in row['paired_deltas'].values():
                value.update(mean=None,sample_std=None,n=0,values=[])
        created['progress']=dict(trial_id=first['id'],round_index=1,current=first['prompt_id'],phase='waiting_for_model',tail=['正在执行第一轮，尚未取得正式成绩'],
            timing=dict(initial_batch=batch,active_batch_id=batch['id'],batches=[batch]),
            live=dict(run_id=first['run_id'],phase='waiting_for_model',usage=dict(requests=1,tool_calls=0,input_tokens=0,output_tokens=0),finding_count=0,audit_elapsed_seconds=12,audit_started_at=current_time.isoformat(),heartbeat_at=fresh_stamp(),last_event_id=150,last_event_at=fresh_stamp()))


    def handle(route):
        req=route.request
        url=urlsplit(req.url)
        path=url.path.removeprefix('/api')
        query=parse_qs(url.query)
        calls.append(path)
        if path=='/prompts':
            if req.method=='GET':
                if hold_catalog[0]:
                    held_catalog.append(route)
                    return
                fixture.json(route,[item for item in prompts if not query.get('kind') or item.get('kind')==query['kind'][0]])
            elif req.method=='POST':
                writes.append((path,req.post_data_json))
                value=dict(req.post_data_json,id='derived-strategy',builtin=False,phase='custom',used_by_runs=0,used_by_experiments=0,created_at=STAMP)
                prompts.append(value)
                fixture.json(route,value,201)
            else:
                raise AssertionError(f'Unexpected prompt write: {req.method}')
        elif path=='/prompt-experiments' and req.method=='GET':
            fixture.json(route,history)
        elif path=='/prompt-experiments' and req.method=='POST':
            body=req.post_data_json
            writes.append((path,body))
            assert body['protocol']=='lab30-full-v2'
            assert body['prompt_ids']==IDS and body['baseline_prompt_id']==IDS[0]
            assert body['repeats']==3 and body['run_limits']==dict(responses=256,tools=2048,seconds=720)
            assert 'units_limit' not in body and 'scenario' not in body
            assert body['experiment_wall_seconds']==7200 and body['budgets']['seconds']==720
            created=copy.deepcopy(full)
            created.update(id='new-comparison',status='running')
            make_running(created)
            history.insert(0,created)
            fixture.json(route,created,201)
        elif path=='/prompt-experiments/slow-comparison':
            held.append(route)
        elif path.startswith('/prompt-experiments/'):
            parts=path.split('/')
            row=next((item for item in history if item['id']==parts[2]),None)
            if not row:
                fixture.json(route,dict(detail='模拟实验不存在'),404)
            elif len(parts)==3:
                if fail_detail[0]:
                    fail_detail[0]=False
                    fixture.json(route,dict(detail='模拟成绩读取失败'),503)
                else:
                    fixture.json(route,row)
            elif parts[3]=='cancel':
                writes.append((path,req.post_data_json))
                row['status']='cancelled'
                fixture.json(route,row)
            elif parts[3]=='report':
                fixture.json(route,dict(report='test only'))
            elif parts[3]=='trials':
                trial=next(t for t in row['trials'] if t['id']==parts[4])
                if len(parts)==5:
                    if row['id']=='new-comparison':
                        fixture.json(route,dict(trial=trial,attempt=trial['attempts'][-1],run=dict(id='isolated-live-run',execution_summary=dict(phase=row['progress']['phase'])),findings=[],score=None,events=live_events[-100:],event_cursor=live_events[-1]['id'],has_earlier=len(live_events)>100,source_available=True))
                        return
                    finding=dict(id='finding-one',title='冻结源码证据示例',vulnerability_type='auth_bypass',category='task_goal',summary='独立试次的实际发现。',disposition='open',validation_state='candidate',input_source='request',propagation='service',dangerous_operation='database',protection='missing',evidence=[dict(path='shop/index.php',start_line=10,end_line=10)])
                    fixture.json(route,dict(trial=trial,score=trial['score'],findings=[finding],run=dict(id='isolated-run',execution_summary=dict(phase='task_execute')),events=[dict(id=1,run_id='isolated-run',kind='tool_called',actor_role='worker',payload=dict(tool='read_source'),created_at=STAMP)],source_available=True))
                elif parts[5]=='source':
                    assert query['path']==['shop/index.php']
                    if fail_source[0]:
                        fail_source[0]=False
                        fixture.json(route,dict(detail='模拟冻结源码缺失'),404)
                    else:
                        fixture.json(route,dict(path='shop/index.php',lines=[dict(number=10,text='// scoped frozen source evidence')]))
                elif parts[5]=='events':
                    if row['id']=='new-comparison':
                        event_reads.append(query)
                        limit=int(query.get('limit',['100'])[0])
                        if 'before' in query:
                            rows=[item for item in live_events if item['id']<int(query['before'][0])]
                            selected_events=rows[-limit:]
                        else:
                            rows=[item for item in live_events if item['id']>int(query.get('after',['0'])[0])]
                            selected_events=rows[:limit]
                        fixture.json(route,dict(events=selected_events,remaining=len(rows)-len(selected_events)))
                    else:
                        fixture.json(route,dict(events=[],remaining=False))
                elif parts[5]=='retry':
                    writes.append((path,req.post_data_json))
                    trial['attempts'].append(dict(id='retry-attempt',attempt_no=2,status='queued',evaluation_status='pending'))
                    trial.update(status='queued',evaluation_status='pending',can_retry=False)
                    row['status']='running'
                    fixture.json(route,row)
                elif parts[5]=='report':
                    fixture.json(route,dict(report='scoped report'))
                else:
                    raise AssertionError(f'Unexpected scoped request {path}')
            else:
                raise AssertionError(f'Unexpected experiment request {path}')
        else:
            fixture.handle(route)

    checks=Checks()
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path=os.environ.get('CHROME_BIN'))
        page=browser.new_page(viewport=dict(width=1440,height=1000))
        page.set_default_timeout(10000)
        errors=[]
        page.on('pageerror',lambda exc:errors.append(str(exc)))
        page.route('**/api/**',handle)
        goto(page,args.base,'#experiments')
        expect(page.get_by_role('button',name='冻结配置并开始对比')).to_be_enabled()
        expect(page.get_by_label('冻结基线',exact=True)).to_have_value(IDS[0])
        expect(page.get_by_label('每版本重复次数',exact=True)).to_have_value('3')
        expect(page.locator('.exp-notice').first).to_contain_text('9 次限时审计')
        expect(page.locator('.exp-notice').first).to_contain_text('7200 秒')
        page.get_by_role('button',name='统一预算设置',exact=True).click()
        page.get_by_label('每次限时审计总预算秒',exact=True).fill('721')
        expect(page.get_by_role('button',name='冻结配置并开始对比')).to_be_disabled()
        page.get_by_label('每次限时审计总预算秒',exact=True).fill('720')
        page.get_by_role('button',name='冻结配置并开始对比').click()
        expect(page).to_have_url(args.base+'/#experiments/new-comparison')
        expect(page.get_by_role('button',name='取消实验',exact=True)).to_be_visible()
        panel=page.get_by_role('region',name='实时审计进度')
        expect(panel).to_contain_text('已结束 0 / 9')
        expect(panel).to_contain_text('等待模型响应')
        expect(panel).to_contain_text('1 / 0')
        created=history[0]
        created['progress']['live'].update(usage=dict(requests=2,tool_calls=7,input_tokens=400,output_tokens=40),finding_count=1,heartbeat_at=fresh_stamp())
        created['progress'].update(phase='task_execute')
        created['progress']['live']['phase']='task_execute'
        expect(panel).to_contain_text('2 / 7',timeout=6000)
        expect(panel).to_contain_text('源码取证')
        checks.passed('a genuine running first trial reports phase, heartbeat and counters before any score exists')
        page.get_by_role('button',name='查看当前试次与日志',exact=True).click()
        page.get_by_role('button',name='实际审计日志 · 100 条',exact=True).click()
        expect(page.locator('.exp-events details')).to_have_count(100)
        assert page.locator('.exp-events summary').first.inner_text().startswith('#51')
        live_events.extend(dict(id=n,run_id='isolated-live-run',kind='live_event',actor_role='worker',payload=dict(message=f'live-event-{n}'),created_at=STAMP) for n in range(151,261))
        created['progress']['live'].update(last_event_id=260,heartbeat_at=fresh_stamp())
        expect(page.locator('.exp-events details')).to_have_count(210,timeout=6000)
        expect(page.locator('.exp-events summary').last).to_contain_text('#260')
        assert any(query.get('after')==['150'] for query in event_reads),event_reads
        page.locator('.exp-events').evaluate('(box)=>box.scrollTop=100')
        before_scroll=page.locator('.exp-events').evaluate('(box)=>box.scrollTop')
        live_events.extend(dict(id=n,run_id='isolated-live-run',kind='live_event',actor_role='worker',payload=dict(message=f'live-event-{n}'),created_at=STAMP) for n in range(261,281))
        expect(page.locator('.exp-events details')).to_have_count(230,timeout=6000)
        assert abs(page.locator('.exp-events').evaluate('(box)=>box.scrollTop')-before_scroll)<=1
        page.get_by_role('button',name='读取更早事件',exact=True).click()
        expect(page.locator('.exp-events details')).to_have_count(280)
        assert any(query.get('before')==['51'] for query in event_reads),event_reads
        assert page.locator('.exp-events').evaluate('(box)=>box.scrollTop')>before_scroll
        checks.passed('latest 100 events drain more than 100 new events automatically and historical paging preserves the reading position')
        page.get_by_role('tab',name='效果总览',exact=True).click()
        hold_catalog[0]=True
        page.reload(wait_until='domcontentloaded')
        expect(page.get_by_role('region',name='实时审计进度')).to_be_visible(timeout=3000)
        expect(page.get_by_role('alert')).to_contain_text('策略库：读取超时',timeout=13000)
        expect(page.get_by_role('region',name='实时审计进度')).to_contain_text('2 / 7')
        hold_catalog[0]=False
        page.get_by_role('button',name='重试读取',exact=True).click()
        expect(page.get_by_role('alert')).to_have_count(0)
        for pending in held_catalog:
            try: fixture.json(pending,prompts)
            except Exception: pass
        checks.passed('a hung strategy catalog times out independently without blocking live experiment detail or erasing data')
        page.evaluate('Object.defineProperty(document,"hidden",{configurable:true,get:()=>true});document.dispatchEvent(new Event("visibilitychange"))')
        created['progress']['live'].update(phase='waiting_for_model',usage=dict(requests=3,tool_calls=9,input_tokens=900,output_tokens=90),heartbeat_at=fresh_stamp())
        created['progress']['phase']='waiting_for_model'
        page.wait_for_timeout(500)
        page.evaluate('Object.defineProperty(document,"hidden",{configurable:true,get:()=>false});document.dispatchEvent(new Event("visibilitychange"))')
        expect(page.get_by_role('region',name='实时审计进度')).to_contain_text('3 / 9',timeout=1500)
        checks.passed('visibility restoration triggers an immediate refresh, including while the model is waiting')
        for theme in ['dark','light']:
            page.evaluate('(theme)=>document.documentElement.dataset.theme=theme',theme)
            for width in [1440,1024,768,390]:
                page.set_viewport_size(dict(width=width,height=1000))
                no_overflow(page,f'live first trial {theme} {width}',checks)
                if args.screenshots and width in (1440,390):
                    args.screenshots.mkdir(parents=True,exist_ok=True)
                    page.screenshot(path=str(args.screenshots/f'running-overview-{theme}-{width}.png'),full_page=True)
        page.set_viewport_size(dict(width=1440,height=1000))
        page.get_by_role('button',name='取消实验',exact=True).click()
        expect(page.get_by_role('button',name='取消实验',exact=True)).to_have_count(0)
        checks.passed('real strategy selection sends full-audit frozen protocol with explicit baseline and total budget; cancellation is scoped')

        goto(page,args.base,'#experiments/full-comparison')
        expect(page.get_by_role('figure',name='各版本 Precision、Recall、F1 均值及样本标准差')).to_be_visible()
        expect(page.locator('.exp-facts')).to_contain_text('提升 +10.0 个百分点')
        expect(page.locator('.exp-facts')).to_contain_text('下降 -12.0 个百分点')
        expect(page.get_by_role('link',name='CSV（3 张表 ZIP）',exact=True)).to_have_attribute('href','/api/prompt-experiments/full-comparison/report?format=csv')
        checks.passed('backend means and sample SD are charted, positive and negative deltas are factual, full export is available')

        page.get_by_role('tab',name='漏洞明细',exact=True).click()
        expect(page.locator('.exp-truth-table tbody tr')).to_have_count(30)
        expect(page.get_by_role('combobox',name='类别筛选')).to_have_count(1)
        page.get_by_role('combobox',name='轮次筛选').select_option('1')
        page.get_by_role('button',name='01 W0 基础审计 命中',exact=True).click()
        expect(page.get_by_role('region',name='试次详情')).to_be_visible()
        expect(page.get_by_role('region',name='试次详情')).to_contain_text('实际读取：20 / 69')
        page.get_by_role('button',name='冻结源码证据示例 · auth_bypass',exact=True).click()
        page.get_by_role('button',name='shop/index.php:10–10',exact=True).click()
        expect(page.get_by_role('region',name='试次证据源码')).to_contain_text('scoped frozen source evidence')
        assert not any(path.startswith('/snapshots/') and path.endswith('/source') for path in calls)
        page.reload(wait_until='domcontentloaded')
        expect(page.get_by_role('combobox',name='轮次筛选')).to_have_value('1')
        expect(page.get_by_role('region',name='试次详情')).to_be_visible()
        checks.passed('30 truths and per-round evidence restore from URL and use isolated trial endpoints instead of main snapshots/runs')

        page.get_by_role('tab',name='版本与冻结条件',exact=True).click()
        page.get_by_role('combobox',name='提示词差异版本').select_option(IDS[1])
        expect(page.locator('.exp-diff')).to_contain_text('增加证据与防护核对')
        page.get_by_role('combobox',name='提示词差异版本').select_option(IDS[2])
        expect(page.locator('.exp-diff')).to_contain_text('增加跨文件业务前提')
        page.get_by_role('tab',name='逐轮运行记录',exact=True).click()
        expect(page.locator('table').first.locator('tbody tr')).to_have_count(9)
        expect(page.locator('table').first).to_contain_text('run_budget_exhausted')
        checks.passed('frozen strategy diff, nine trial rows, and valid budget-exhausted outcomes remain inspectable')

        goto(page,args.base,'#prompts')
        page.get_by_role('button',name='实验已引用策略',exact=False).click()
        expect(page.get_by_role('textbox',name='正文',exact=False)).to_have_attribute('readonly','')
        expect(page.get_by_role('button',name='删除提示词草稿',exact=True)).to_be_disabled()
        page.get_by_role('button',name='基于此版本另存',exact=True).click()
        page.get_by_role('textbox',name='标签',exact=True).fill('派生审计策略')
        page.get_by_role('button',name='保存新版本',exact=True).click()
        expect(page.get_by_role('status')).to_contain_text('已另存为新版本')
        assert writes[-1][1]['kind']=='worker_strategy' and writes[-1][1]['parent_id']=='used-custom'
        checks.passed('experiment references make prompt text and deletion readonly, with compatible strategy derivation')

        goto(page,args.base,'#experiments/old-comparison')
        expect(page.locator('.exp-notice')).to_contain_text('旧版单元协议 · 只读')
        expect(page.get_by_role('tab')).to_have_count(0)
        checks.passed('legacy unit experiments remain separately labeled and readonly')
        goto(page,args.base,'#experiments/missing')
        expect(page.get_by_role('alert')).to_contain_text('模拟实验不存在')
        fail_detail[0]=True
        goto(page,args.base,'#experiments/full-comparison')
        expect(page.get_by_role('alert')).to_contain_text('模拟成绩读取失败')
        page.get_by_role('button',name='重试读取',exact=True).click()
        expect(page.get_by_role('alert')).to_have_count(0)
        checks.passed('404 and failed reads are explicit and retryable')

        goto(page,args.base,'#experiments/zero-report')
        expect(page.locator('.exp-metric-table tbody tr').first).to_contain_text('0.0%')
        expect(page.locator('.exp-metric-table tbody tr').first.locator('td').first).to_have_text('—')
        expect(page.locator('.exp-notice').first).to_contain_text('共同有效 3 / 3')
        checks.passed('zero-report precision is missing while actual zero Recall/F1 remain visible')

        goto(page,args.base,'#experiments/incomplete-comparison')
        expect(page.locator('.exp-notice').first).to_contain_text('初步结果')
        expect(page.locator('.exp-notice').first).to_contain_text('共同有效 2 / 3')
        page.get_by_role('tab',name='逐轮运行记录',exact=True).click()
        page.get_by_role('button',name='查看试次',exact=True).last.click()
        expect(page.get_by_role('region',name='试次详情')).to_contain_text('无效试次')
        page.get_by_role('button',name='使用冻结配置补跑一次',exact=True).click()
        expect(page.get_by_role('button',name='使用冻结配置补跑一次',exact=True)).to_have_count(0)
        expect(page.get_by_role('button',name='取消实验',exact=True)).to_be_visible()
        page.get_by_role('button',name='取消实验',exact=True).click()
        checks.passed('incomplete cohorts are preliminary and invalid attempts can be explicitly retried once with retained history')

        goto(page,args.base,'#experiments/full-comparison?tab=trials&trial=trial-1-0')
        page.get_by_role('button',name='冻结源码证据示例 · auth_bypass',exact=True).click()
        fail_source[0]=True
        page.get_by_role('button',name='shop/index.php:10–10',exact=True).click()
        expect(page.get_by_role('alert')).to_contain_text('模拟冻结源码缺失')
        checks.passed('missing scoped evidence is explicit and never falls back to a different snapshot')

        goto(page,args.base,'#experiments/slow-comparison')
        page.wait_for_timeout(200)
        page.evaluate('location.hash="#experiments/full-comparison"')
        expect(page.locator('.exp-facts')).to_be_visible()
        for pending in held:
            try:
                fixture.json(pending,dict(full,id='slow-comparison'))
            except Exception:
                pass  # Browser abort can release the route before the simulated response.
        page.wait_for_timeout(200)
        expect(page).to_have_url(args.base+'/#experiments/full-comparison')
        expect(page.locator('.exp-result-head')).to_contain_text('full-comparison')
        checks.passed('a delayed previous experiment response cannot replace the newly selected experiment')

        for theme in ['dark','light']:
            page.set_viewport_size(dict(width=1440,height=1000))
            page.evaluate('(theme)=>{localStorage.setItem("audit-theme",theme);document.documentElement.dataset.theme=theme}',theme)
            for suffix in ['#experiments','#experiments/full-comparison','#experiments/full-comparison?tab=findings','#experiments/full-comparison?tab=prompts','#experiments/full-comparison?tab=trials']:
                goto(page,args.base,suffix)
                expect(page.get_by_role('heading',name='Prompt 实验',exact=True)).to_be_visible()
                page.wait_for_timeout(120)
                for width in [1440,1024,768,390]:
                    page.set_viewport_size(dict(width=width,height=1000))
                    no_overflow(page,f'{theme} {width} {suffix}',checks)
                    if args.screenshots and width in (1440,390):
                        args.screenshots.mkdir(parents=True,exist_ok=True)
                        name=f'{theme}-{width}-{suffix.replace("#","").replace("/","-").replace("?","-").replace("=","-")}.png'
                        page.screenshot(path=str(args.screenshots/name),full_page=True)
        assert not errors,errors
        assert not fixture.unexpected,fixture.unexpected
        browser.close()
    print(f'PASS {checks.count} prompt comparison browser checks; all APIs mocked',flush=True)


if __name__=='__main__':
    main()
