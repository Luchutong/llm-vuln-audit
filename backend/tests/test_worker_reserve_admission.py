"""An unaffordable next lease must not oscillate with its own review reservation."""
import asyncio
import json

import pytest

from audit import worker as worker_module
from audit.execution_state import CURRENT_EXECUTION
from tests.test_host_queue import hosted, add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_goal_tasks import make_worker, proposal


def test_prospective_worker_reserve_ends_discovery_without_repeated_claims(hosted,monkeypatch):
    store,repo,run=hosted
    add_claim(store,run,1)
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='保留待取证的真实源码方向',tasks=[proposal('unaffordable')])
    workflow=store.workflow_state(run['id'])
    workflow.update(limits=dict(discovery=9,poc=0,review=3),used=dict(discovery=6,poc=0,review=0),
                    source='derived',poc_reserved_seconds=0)
    store._write('UPDATE run_execution_state SET limits=?,responses_used=6,workflow=? WHERE run_id=?',
        (json.dumps(dict(responses=12,tools=100,seconds=3600)),json.dumps(workflow),run['id']))
    store._write('UPDATE runs SET poc_policy=? WHERE id=?',(json.dumps(dict(mode='off',enabled=False)),run['id']))
    # Without a prospective worker, an idle budget appears to have three calls.
    quiet=store.refresh_review_reserve(run['id'],repo)
    assert quiet['remaining']['discovery']>0
    assert not store.refresh_review_reserve(run['id'],repo,additional_workers=1)['review_reserve']['funded']
    # Releasing that proposed lease recreates the observed loop on the old code.
    assert store.refresh_review_reserve(run['id'],repo)['remaining']['discovery']>0
    async def no_worker(**kwargs):
        pytest.fail('A lease unable to fund review must not enter the worker')
    phases=[]
    async def planner(**kwargs):
        batch=kwargs['run_context']['review_batch'];phases.append(batch['phase'])
        CURRENT_EXECUTION.get().admit('responses')
        return dict(decision=dict(goal_state='continue',basis_summary='基于冻结源码完成有限终审。',review_batch_id=batch['id'],
            review_decisions=[dict(item_id=i['item_id'],revision=i['revision'],decision='accept',rationale='源码引用完整且支持当前独立结论。') for i in batch['items']]),
            usage=dict(requests=1),terminal_reason='completed')
    monkeypatch.setattr(worker_module,'pursue_planner_task',no_worker)
    monkeypatch.setattr(worker_module,'plan_audit_frontier',planner)
    asyncio.run(asyncio.wait_for(make_worker(store,repo)._execute(store.get_run(run['id'])),timeout=8))
    final=store.get_run(run['id'])
    assert final['status']=='inconclusive' and phases==['final']
    assert not store._rows("SELECT id FROM events WHERE run_id=? AND kind='planner_task_started'",(run['id'],))
    assert final['execution_summary']['run_usage']['responses']==7
    assert sum(final['execution_summary']['workflow']['limits'].values())==12
