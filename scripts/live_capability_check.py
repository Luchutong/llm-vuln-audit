#!/usr/bin/env python3
"""Explicit opt-in live-model pilot, isolated from the user's audit database.

Run with the backend uv environment. Same-source policy pairs are a small
engineering pilot, NOT a benchmark recall or whole-version A/B measurement.
Credentials stay in memory; only public model identity and bounded metrics leave it.
"""
import argparse
import asyncio
import hashlib
import io
import json
import os
import sqlite3
import sys
import time
import zipfile
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def configured_model():
    from audit.config import Settings, load_env_file
    from cryptography.fernet import Fernet
    if (ROOT / '.env').exists():
        load_env_file(ROOT / '.env')
    settings = Settings.load()
    db_path = ROOT / 'data' / 'audit.db'
    if db_path.exists():
        with sqlite3.connect(f'file:{db_path}?mode=ro', uri=True) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute('SELECT p.* FROM model_profiles p JOIN model_selection s ON p.id=s.selected_profile_id WHERE s.id=1').fetchone()
        if row and row['credential_source'] != 'environment':
            key = (db_path.parent / '.model-config.key').read_bytes().strip()
            secret = Fernet(key).decrypt(row['api_key_secret'].encode()).decode()
            settings.model = replace(settings.model, model=row['model'], base_url=row['base_url'], api_key=secret)
    if not settings.model.configured:
        raise RuntimeError('No configured live model; credentials were not printed')
    return settings


def catalog_archive(source):
    # Read real source only, never the answer archive or offline truth labels.
    selected = ['app/public/catalog/index.php', 'app/public/catalog/detail.php',
                'app/public/catalog/greeting.php', 'app/src/bootstrap.php']
    out = io.BytesIO()
    with zipfile.ZipFile(source) as upstream, zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in selected:
            archive.writestr(zipfile.ZipInfo(path, (2026, 1, 1, 0, 0, 0)), upstream.read('lab30-shop/' + path))
    return out.getvalue()


async def trial(settings, args, index, policy, archive):
    import httpx
    from audit import app as app_module
    from audit.app import Services
    from audit.frozen_reports import materialize
    directory = args.output / f'pair-{index}-{policy}'
    directory.mkdir(parents=True, exist_ok=False)
    os.environ['LAB30_SEED'] = '0'
    # off is the tested mode; runner is disabled independently as a second bound.
    service = Services(replace(settings, data_dir=directory, poc=replace(settings.poc, enabled=False, runner_url='', runner_token='')))
    app_module.app.state.services = service
    transport = httpx.ASGITransport(app=app_module.app)
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(transport=transport, base_url='http://isolated-test', timeout=30) as api:
            uploaded = await api.post('/api/snapshots', files={'file':('lab30-catalog-pilot.zip', archive, 'application/zip')})
            uploaded.raise_for_status()
            snapshot = uploaded.json()
            created = await api.post('/api/runs', json={
                'snapshot_id':snapshot['id'], 'poc_mode':'off',
                'budgets': {'responses':12,'tools':40,'seconds':args.seconds},
                'run_limits':{'responses':args.responses,'tools':192,'seconds':args.seconds},
                'task':{'objective':'仅审计目录检索入口到数据库调用链的 SQL 注入。其他风险保留为附带发现，不作为 SQL 注入目标达成。',
                        'scenario':'sqli', 'completion_policy':'coverage_review', 'baseline_policy':'fresh',
                        'workflow_policy':'discovery_first','orchestration_policy':'host-queue-v1',
                        'risk_coverage_policy':args.risk,
                        'max_workers':1,'max_total_attempts':12,'max_planner_rounds':12,'require_poc':False}})
            created.raise_for_status()
            run_id = created.json()['id']
            if policy == 'legacy-policy':
                task = service.store.get_run(run_id)['task_spec']
                for field in ('capability_policy','audit_focus','risk_obligation_set','comparison_policy','poc_scope_policy'):
                    task.pop(field, None)
                service.store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(task),run_id))
            print(json.dumps({'event':'live_start','pair':index,'policy':policy,'run_id':run_id,'responses_limit':args.responses,'seconds_limit':args.seconds}), flush=True)
            run = service.store.claim_next_run()
            service.worker._pauses[run_id] = asyncio.Event()
            await service.worker._execute(run)
            result = await api.get(f'/api/runs/{run_id}')
            result.raise_for_status()
            run = service.store.get_run(run_id)
            saved = materialize(service.store, service.repository, run_id)
            facts = saved['facts']
            for view in ('audit','vulnerabilities','archive'):
                for format in ('markdown','json','zip'):
                    response = await api.get(f'/api/runs/{run_id}/report',params={'view':view,'format':format})
                    response.raise_for_status()
                    suffix = 'md' if format == 'markdown' else format
                    (directory / f'{view}.{suffix}').write_bytes(response.content)
            for entry in facts['canonical_findings']:
                response = await api.get(f'/api/runs/{run_id}/canonical-findings/{entry["canonical_id"]}/report',params={'format':'zip'})
                response.raise_for_status()
                (directory / f'finding-{entry["canonical_id"]}.zip').write_bytes(response.content)
            events = service.store._rows('SELECT kind,payload FROM events WHERE run_id=?',(run_id,))
            kinds = [event['kind'] for event in events]
            usage = run['execution_summary']['run_usage']
            assert usage['responses'] <= args.responses
            assert not service.store.list_run_verification_jobs(run_id)
            assert run['status'] not in {'running','pending','paused'}
            assert all(e['frozen_claim']['verification_status'] != 'verified' for e in facts['canonical_findings'])
            summary = {'pair':index,'policy':policy,'run_id':run_id,'status':run['status'],'model':settings.model.model,
                       'archive_sha256':hashlib.sha256(archive).hexdigest(),'usage':usage,'counts':facts['counts'],
                       'audit_complete':facts['run_outcome']['audit_complete'],
                       'relations': facts['run_outcome'].get('focus'),
                       'types':[e['frozen_claim'].get('vulnerability_type') for e in facts['canonical_findings']],
                       'parse_errors':kinds.count('agent_parse_error'),'output_rejected':kinds.count('agent_output_rejected'),
                       'poc_jobs':0,'wall_seconds':round(time.monotonic()-started,2),
                       'quality':facts['quality_result']['publishability'],
                       'stop_reason':run['execution_summary']['stop_reason']}
            (directory/'metrics.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
            print(json.dumps({'event':'live_done',**summary},ensure_ascii=False),flush=True)
            return summary
    finally:
        await service.worker.stop()
        service.store.close()


async def main(args):
    settings = configured_model()
    archive = catalog_archive(args.source)
    results = []
    for index in range(1,args.pairs+1):
        order = (['legacy-policy','current-policy'] if index % 2 else ['current-policy','legacy-policy']) if args.policies == 'paired' else ['current-policy']
        for policy in order:
            results.append(await trial(settings,args,index,policy,archive))
            (args.output/'results.json').write_text(json.dumps({'scope':'真实 Lab30 目录模块子集；同代码策略开关配对，非全量召回评测。','runs':results},ensure_ascii=False,indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--pairs',type=int,choices=(1,2,3),default=1)
    parser.add_argument('--responses',type=int,default=36)
    parser.add_argument('--seconds',type=int,default=240)
    parser.add_argument('--risk',choices=('off','bounded-v1'),default='off')
    parser.add_argument('--policies',choices=('paired','current'),default='paired')
    args = parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    asyncio.run(main(args))
