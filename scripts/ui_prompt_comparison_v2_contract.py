#!/usr/bin/env python3
"""Browser contract check against real FastAPI routes and temporary experiment databases.

All browser /api requests go through a real TestClient without entering the production
lifespan. Nine completed fixture trials are seeded directly into temporary stores and
scored by the real v2 evaluator. No audit worker, model, POC or user data is used.

Serve frontend/dist on a spare localhost port and pass the URL. Requires the backend
Python dependencies and Playwright in the same interpreter environment.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
os.environ['LAB30_SEED'] = '0'

from fastapi.testclient import TestClient
from playwright.sync_api import expect, sync_playwright
from audit import app as app_module
from audit.config import ModelConfig, Settings
from audit.db import Store, now
from audit.full_comparison import PROTOCOL, OBJECTIVE
from audit.prompt_evaluation import DEFAULT_ANCHORS_PATH, DEFAULT_TRUTH_PATH, evaluate_v2, validate_assets
from audit.prompt_experiments import SOURCE_ZIP
from audit.source import SourceRepository
from audit.worker_strategies import builtin_worker_strategies, freeze_worker_strategy
from ui_smoke import Checks, goto, no_overflow


def fixture_services(directory: Path):
    """Use completed fixture records rather than scheduling an async audit at any point."""
    settings = Settings(data_dir=directory, model=ModelConfig(
        model='offline-contract-fixture', base_url='http://127.0.0.1:1/v1', api_key='not-a-real-key'))
    state = app_module.Services(settings)
    runner = state.prompt_experiments.full
    ident = 'e' * 16
    folder = runner._directory(ident)
    frozen = folder / 'frozen'
    frozen.mkdir(parents=True)
    for source, name in [(SOURCE_ZIP,'source.zip'),(DEFAULT_TRUTH_PATH,'truth.json'),(DEFAULT_ANCHORS_PATH,'anchors.json')]:
        (frozen / name).write_bytes(Path(source).read_bytes())
    assets = validate_assets(frozen/'source.zip',frozen/'truth.json',frozen/'anchors.json')
    truth = json.loads((frozen/'truth.json').read_text())
    anchors = json.loads((frozen/'anchors.json').read_text())
    variants = [freeze_worker_strategy(item) for item in builtin_worker_strategies()]
    for variant in variants:
        variant['sha256'] = variant['text_sha256']
    manifest = dict(protocol=PROTOCOL,scoring_protocol='lab30-v2',created_at=now(),variants=variants,
                    baseline_prompt_id=variants[0]['id'],repeats=3,
                    model=dict(model=settings.model.model,base_url=settings.model.public_base_url(),thinking=settings.model.thinking),
                    budgets=dict(responses=24,tools=96,seconds=1800),run_limits=dict(responses=256,tools=2048,seconds=1800),
                    source_sha256=hashlib.sha256((frozen/'source.zip').read_bytes()).hexdigest(),assets=assets,
                    task_spec=dict(objective=OBJECTIVE),poc_mode='off',code=dict(commit='offline-contract-fixture',dirty=False),
                    order=[[v['id'] for v in variants[r:]+variants[:r]] for r in range(3)])
    trials=[]
    source_bytes=(frozen/'source.zip').read_bytes()
    # A second attempt on one slot exercises actual history selection. Its first
    # attempt is deliberately invalid and cannot contribute to the summary.
    for round_index in range(1,4):
        for index, variant in enumerate(variants):
            trial_id=f'{round_index*100+index:016x}'
            trial=dict(id=trial_id,round_index=round_index,prompt_id=variant['id'],attempts=[])
            count = 2 if (round_index,index)==(1,0) else 1
            for attempt_no in range(1,count+1):
                work=folder/'trials'/trial_id/f'attempt-{attempt_no}'
                repository=SourceRepository(work)
                snapshot=repository.import_zip(source_bytes,'official-lab30-source.zip')
                store=Store(work/'audit.db')
                store.add_snapshot(snapshot)
                run_id=f'fixture-run-{round_index}-{index}-{attempt_no}'
                store.create_run(dict(id=run_id,snapshot_id=snapshot['id'],snapshot_name=snapshot['name'],
                                      scope=[],scope_mode='snapshot',prompt_id=variant['id'],prompt_label=variant['label'],
                                      prompt_text=variant['text'],model=settings.model.model,
                                      budgets=manifest['budgets'],run_limits=manifest['run_limits'],created_at=now()))
                selected_anchors=anchors['vulnerabilities'][:[8,12,10][index]] if attempt_no==count else anchors['vulnerabilities'][:1]
                for row in selected_anchors:
                    location=row['scoring_locations'][0]
                    path='lab30-shop/'+location['path']
                    reference=dict(snapshot_id=snapshot['id'],path=path,start_line=location['line'],end_line=location['line'])
                    finding_id=f'fixture-finding-{round_index}-{index}-{attempt_no}-{row["id"]}'
                    store.add_finding(dict(id=finding_id,run_id=run_id,unit_id=f'fixture-slot-{row["id"]}',
                        fingerprint=finding_id,category='task_goal',finding_kind='vulnerability',
                        title=f'离线契约样例 {row["id"]} · 第 {attempt_no} 次',severity='unknown',
                        summary='固定离线夹具，不是真实模型审计成绩。',evidence=[reference],input_source='fixture input',
                        propagation='fixture propagation',dangerous_operation='fixture sink',protection='fixture defence',
                        preconditions=[],missing_context=[],poc=None,remediation='fixture remediation',
                        vulnerability_type=row['class'],primary_location=dict(path=path,line=location['line']),
                        validation_state='candidate',validation_errors=[],created_at=now()))
                store.append_event(run_id,None,'fixture_contract_event',dict(attempt=attempt_no,note='No model was called'))
                store.update_run(run_id,status='completed',finished_at=now())
                score=evaluate_v2(truth,store.list_findings(run_id),anchors)
                usage=dict(requests=0,tool_calls=0,input_tokens=0,output_tokens=0,total_tokens=0)
                attempt=dict(id=f'{round_index*10000+index*10+attempt_no:016x}',attempt_no=attempt_no,run_id=run_id,
                    status='finished',evaluation_status='valid' if attempt_no==count else 'invalid',
                    stop_reason=dict(code='fixture_complete' if attempt_no==count else 'fixture_initial_failure'),
                    score=score if attempt_no==count else None,usage=usage,duration_seconds=0,
                    read_coverage=dict(read_files=0,total_files=len(snapshot['files']),read_lines=0,total_lines=0,file_ratio=0,line_ratio=None))
                trial['attempts'].append(attempt)
                store.close()
            trial.update({key:value for key,value in trial['attempts'][-1].items() if key not in {'id','attempt_no'}})
            trials.append(trial)
    summary=runner._summary(manifest,trials,folder)
    assert summary['complete_round_count']==3
    assert [v['metrics']['TP']['mean'] for v in summary['variants']]==[8,12,10]
    (folder/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False))
    state.store.add_full_prompt_experiment(dict(id=ident,created_at=now(),status='completed',variants=[v['id'] for v in variants],
        model=settings.model.label,budgets=manifest['budgets'],manifest=manifest,trials=trials,summary=summary))
    state.store.update_prompt_experiment(ident,finished_at=now())
    return state,ident,trials


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base')
    args=parser.parse_args()
    checks=Checks()
    with tempfile.TemporaryDirectory(prefix='vuln-audit-ui-contract-') as temporary:
        state,ident,trials=fixture_services(Path(temporary))
        app_module.app.state.services=state
        client=TestClient(app_module.app)  # Do not enter lifespan: it would start a worker.
        real_requests=[]
        def handle(route):
            request=route.request
            assert request.method=='GET',f'Unexpected state-changing request: {request.method} {request.url}'
            from urllib.parse import urlsplit
            url=urlsplit(request.url)
            path=url.path+('?' + url.query if url.query else '')
            response=client.get(path)
            real_requests.append((path,response.status_code))
            route.fulfill(status=response.status_code,body=response.content,headers=dict(response.headers))
        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(executable_path=os.environ.get('CHROME_BIN'))
                page=browser.new_page(viewport=dict(width=1440,height=1000))
                errors=[]
                page.on('pageerror',lambda error:errors.append(str(error)))
                page.route('**/api/**',handle)
                goto(page,args.base,f'#experiments/{ident}')
                expect(page.locator('.exp-notice').first).to_contain_text('共同有效 3 / 3')
                expect(page.locator('.exp-metric-table tbody tr')).to_have_count(3)
                expect(page.locator('.exp-metric-table tbody tr').first).to_contain_text('26.7%')
                expect(page.locator('.exp-facts')).to_contain_text('提升')
                checks.passed('real FullComparisonRunner/Store/evaluator statistics render through real FastAPI routes')
                page.get_by_role('tab',name='漏洞明细',exact=True).click()
                expect(page.locator('.exp-truth-table tbody tr')).to_have_count(30)
                page.get_by_role('tab',name='版本与冻结条件',exact=True).click()
                expect(page.locator('.exp-diff')).to_be_visible()
                checks.passed('actual official 30-item truth matrix and frozen builtin strategy diff agree with the API')
                first=trials[0]
                page.evaluate('(hash)=>location.hash=hash',f'#experiments/{ident}?tab=trials&trial={first["id"]}')
                expect(page.get_by_role('combobox',name='查看执行版本')).to_have_value('2')
                expect(page.get_by_role('button',name='离线契约样例 01 · 第 2 次 · sqli',exact=True)).to_be_visible()
                page.get_by_role('button',name='离线契约样例 01 · 第 2 次 · sqli',exact=True).click()
                page.get_by_role('button',name='lab30-shop/app/public/catalog/index.php:4–4',exact=True).click()
                expect(page.get_by_role('region',name='试次证据源码')).to_contain_text('db()->query')
                report=page.get_by_role('link',name='试次报告',exact=True).get_attribute('href')
                response=client.get(report)
                assert response.status_code==200 and '离线契约样例 01' in response.text,response.text[:500]
                checks.passed('actual independent SQLite run, frozen ZIP source and scoped Markdown report are readable')
                page.get_by_role('combobox',name='查看执行版本').select_option('1')
                expect(page.get_by_role('region',name='试次详情')).to_contain_text('fixture_initial_failure')
                expect(page.get_by_role('button',name='离线契约样例 01 · 第 2 次 · sqli',exact=True)).to_have_count(0)
                expect(page.locator('.exp-trial-numbers')).to_have_count(0)
                page.get_by_role('button',name='离线契约样例 01 · 第 1 次 · sqli',exact=True).click()
                page.get_by_role('button',name='lab30-shop/app/public/catalog/index.php:4–4',exact=True).click()
                expect(page.get_by_role('region',name='试次证据源码')).to_contain_text('db()->query')
                assert any('/source?' in path and 'attempt=1' in path for path,_ in real_requests)
                report=page.get_by_role('link',name='试次报告',exact=True).get_attribute('href')
                assert 'attempt=1' in report
                response=client.get(report)
                assert response.status_code==200 and 'fixture-finding-1-0-2-01' not in response.text
                page.reload(wait_until='domcontentloaded')
                expect(page.get_by_role('combobox',name='查看执行版本')).to_have_value('1')
                expect(page.get_by_role('region',name='试次详情')).to_contain_text('fixture_initial_failure')
                checks.passed('historical attempts restore from URL and cannot leak the current attempt findings or report')
                archive=client.get(f'/api/prompt-experiments/{ident}/report?format=csv')
                assert archive.status_code==200 and archive.headers['content-type'].startswith('application/zip')
                with zipfile.ZipFile(io.BytesIO(archive.content)) as zipped:
                    assert set(zipped.namelist())=={'summary.csv','trials.csv','truth_matrix.csv'}
                    assert len(zipped.read('truth_matrix.csv').decode('utf-8-sig').splitlines())>=31
                assert client.get(f'/api/prompt-experiments/{ident}/report?format=markdown').status_code==200
                assert client.get(f'/api/prompt-experiments/{ident}/report?format=json').json()['summary']['complete_round_count']==3
                checks.passed('all three real report formats use server statistics and CSV is an actual three-table ZIP')
                for theme in ['dark','light']:
                    page.evaluate('(theme)=>document.documentElement.dataset.theme=theme',theme)
                    for width in [1440,1024,768,390]:
                        page.set_viewport_size(dict(width=width,height=1000))
                        no_overflow(page,f'real routes history detail {theme} {width}',checks)
                assert not errors,errors
                failures=[entry for entry in real_requests if entry[1]>=400]
                assert not failures,failures
                assert not state.store.list_runs(),'Fixture experiments must not populate the normal run library'
                assert state.prompt_experiments.full._task is None
                browser.close()
            print(f'PASS {checks.count} real API browser contract checks; no model or worker started',flush=True)
        finally:
            client.close()
            state.store.close()


if __name__=='__main__':
    main()
