#!/usr/bin/env python3
"""Run isolated, fresh full-source trials; evaluate only after each audit terminates.

No findings or answers are inherited. POC off measures static audit behavior; auto
requires a separately prepared local runner. Every valid low score is retained.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from live_capability_check import configured_model
from run_lab30_e2e import OBJECTIVES, CLOSURE_BUDGETS, CLOSURE_LIMITS, CLOSURE_TASK, SCORE_TARGET, score_problems


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temporary.replace(path)


def code_digest():
    digest = hashlib.sha256()
    for path in sorted((ROOT / 'backend/audit').rglob('*')):
        if path.suffix not in {'.py', '.yaml', '.md', '.json'}:
            continue
        digest.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes())
    return digest.hexdigest()


async def trial(settings, args, index, profile, archive):
    import httpx
    from audit import app as app_module
    from audit.app import Services
    from audit.frozen_reports import materialize

    directory = args.output / f'{index:02}-{profile}'
    directory.mkdir(mode=0o700, exist_ok=False)
    os.environ['LAB30_SEED'] = '0'
    policy = settings.poc if args.poc_mode != 'off' else replace(settings.poc, enabled=False, runner_url='', runner_token='')
    service = Services(replace(settings, data_dir=directory, poc=policy))
    app_module.app.state.services = service
    task = {**CLOSURE_TASK, 'objective': OBJECTIVES['all'], 'focus_scope': 'all',
        'completion_policy': 'coverage_review', 'workflow_policy': 'discovery_first',
        'orchestration_policy': 'host-queue-v1', 'review_policy': 'batch-v1',
        'stop_on_achieved': False, 'baseline_policy': 'fresh', 'require_poc': False,
        'risk_coverage_policy': 'bounded-v2' if profile in {'signals', 'optimized'} else 'off',
        'exploration_policy': 'exhaustive-v1' if profile in {'triage', 'optimized'} else 'legacy',
        'role_policy': 'worker-evidence-v2' if profile in {'roles', 'optimized'} else 'legacy',
        'investigation_policy': 'bounded-v1' if profile in {'roles', 'optimized'} else 'legacy'}
    limits = {**CLOSURE_LIMITS, 'seconds': args.seconds, 'responses': args.responses}
    manifest = dict(profile=profile, repetition=index, model=settings.model.model,
        source_sha256=hashlib.sha256(archive).hexdigest(), code_sha256=code_digest(),
        run_limits=limits, task=task, poc_mode=args.poc_mode, score_target=SCORE_TARGET,
        started_at=datetime.now(timezone.utc).isoformat())
    write_json(directory / 'manifest.json', manifest)
    started, heartbeat = time.monotonic(), None
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_module.app), base_url='http://isolated-audit', timeout=60) as api:
            uploaded = await api.post('/api/snapshots', files={'file':('lab30-source.zip', archive, 'application/zip')})
            uploaded.raise_for_status()
            created = await api.post('/api/runs', json=dict(snapshot_id=uploaded.json()['id'], task=task,
                poc_mode=args.poc_mode, budgets=CLOSURE_BUDGETS, run_limits=limits))
            created.raise_for_status()
            run_id = created.json()['id']
            manifest['run_id'] = run_id
            manifest['frozen_task'] = service.store.get_run(run_id)['task_spec']
            write_json(directory / 'manifest.json', manifest)
            print(json.dumps(dict(event='started', run_id=run_id, profile=profile, directory=str(directory))), flush=True)

            async def progress():
                while True:
                    await asyncio.sleep(20)
                    current = service.store.get_run(run_id)
                    print(json.dumps(dict(event='progress', run_id=run_id, status=current['status'],
                        usage=current['execution_summary']['run_usage'], directions=service.store.audit_direction_summary(run_id)['unsettled_total'])), flush=True)
            heartbeat = asyncio.create_task(progress())
            run = service.store.claim_next_run()
            service.worker._pauses[run_id] = asyncio.Event()
            await service.worker._execute(run)
            run = service.store.get_run(run_id)
            if run['status'] in {'pending', 'running', 'paused'}:
                raise RuntimeError('Executor did not reach a terminal state')
            frozen = materialize(service.store, service.repository, run_id)
            facts = frozen['facts']
            # Scorer imports and answer reads happen after the source auditor ends.
            from audit.prompt_evaluation import evaluate_v2
            truth = json.loads((ROOT / 'datasets/lab30-shop/ground_truth.json').read_text())
            anchors = json.loads((ROOT / 'datasets/lab30-shop/scoring_anchors_v2.json').read_text())
            records = service.store.frozen_report(run_id)['input']['findings']
            asserted = evaluate_v2(truth, records, anchors)
            accepted_ids = {entry['frozen_claim']['finding_id'] for entry in facts['canonical_findings'] if entry['final_disposition'] == 'accepted'}
            accepted = evaluate_v2(truth, [record for record in records if record['id'] in accepted_ids], anchors)
            write_json(directory / 'score-asserted.json', asserted)
            write_json(directory / 'score-accepted.json', accepted)
            unchanged = code_digest() == manifest['code_sha256']
            checks = score_problems(accepted, SCORE_TARGET)
            if run['status'] != 'completed' or not facts['run_outcome'].get('audit_complete'):
                checks.append('运行或完整性维度尚未完成')
            if not unchanged:
                checks.append('运行期间宿主源码变化，本次不能充当固定版本验收')
            score_keys = ('TP', 'FN', 'D', 'U', 'FP', 'precision', 'recall', 'f1')
            metrics = dict(run_id=run_id, profile=profile, repetition=index, model=run['model'], status=run['status'],
                stop_reason=run['execution_summary']['stop_reason'], usage=run['execution_summary']['run_usage'],
                elapsed_seconds=round(time.monotonic()-started, 3), counts=facts['counts'],
                asserted={key:asserted[key] for key in score_keys}, accepted={key:accepted[key] for key in score_keys},
                directions=service.store.audit_direction_summary(run_id), risk=service.store.risk_coverage(run_id),
                poc_jobs=len(service.store.list_run_verification_jobs(run_id)),
                code_unchanged=unchanged, failed_checks=checks)
            write_json(directory / 'metrics.json', metrics)
            print(json.dumps(dict(event='finished', run_id=run_id, status=run['status'], accepted=metrics['accepted'], failed_checks=checks), ensure_ascii=False), flush=True)
            return metrics
    finally:
        if heartbeat:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat
        await service.worker.stop()
        service.store.close()


async def main(args):
    settings = configured_model()
    archive = args.source.read_bytes()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = []
    for index in range(1, args.repeats + 1):
        profiles = args.profiles if index % 2 else list(reversed(args.profiles))
        for profile in profiles:
            result = await trial(settings, args, index, profile, archive)
            results.append(result)
            write_json(args.output / 'results.json', dict(scope='新鲜完整源码的隔离实测；off 模式仅表示静态验证', trials=results))
    return int(any(result['failed_checks'] for result in results))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profiles', choices=('baseline', 'triage', 'signals', 'roles', 'optimized'), nargs='+', default=['baseline', 'optimized'])
    parser.add_argument('--repeats', type=int, choices=(1, 2, 3), default=1)
    parser.add_argument('--seconds', type=int, default=CLOSURE_LIMITS['seconds'])
    parser.add_argument('--responses', type=int, default=CLOSURE_LIMITS['responses'])
    parser.add_argument('--poc-mode', choices=('off', 'auto', 'required'), default='off')
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args)))
