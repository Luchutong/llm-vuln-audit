"""Incremental review and resumable exhaustion use the real queue and SQLite ledger."""
import asyncio
import copy
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from audit import worker as worker_module, app as app_module
from audit.budget_checkpoints import grant, pause
from audit.execution_state import CURRENT_EXECUTION
from audit.final_review import canonical_groups
from audit.schemas import BudgetGrantRequest
from tests.test_host_queue import hosted, add_claim, completed_task_with_direction  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_run_continuations import finish, request, decisions
from tests.test_goal_tasks import make_worker
from tests.test_review_closure_repair import risk_batch


def enable(store, run, **values):
    task={**run['task_spec'], 'budget_exhaustion_policy':'pause-v1', 'review_reuse_policy':'incremental-v1', **values}
    store._write('UPDATE runs SET task_spec=? WHERE id=?',(json.dumps(task),run['id']))
    return store.get_run(run['id'])


def payload(**changes):
    return BudgetGrantRequest(request_id='budget-grant-one', stage='poc',responses=8,seconds=60,**changes).model_dump()


def test_poc_exhaustion_pauses_same_stage_without_review_or_frozen_report(hosted,monkeypatch):
    store,repo,run=hosted
    add_claim(store,run,1)
    run=enable(store,run)
    store._write("UPDATE runs SET project_mode='project',poc_policy=? WHERE id=?",(json.dumps(dict(mode='auto',enabled=True)),run['id']))
    workflow=store.workflow_state(run['id'])
    workflow.update(stage='poc',source='derived',limits=dict(discovery=5,poc=8,review=43),used=dict(discovery=5,poc=8,review=0))
    store._write('UPDATE run_execution_state SET limits=?,workflow=?,responses_used=13 WHERE run_id=?',
        (json.dumps(dict(responses=56,tools=200,seconds=3600)),json.dumps(workflow),run['id']))
    async def forbidden(*args,**kwargs):
        pytest.fail('exhausted POC must not invoke review or a new experiment')
    monkeypatch.setattr(worker_module,'plan_audit_frontier',forbidden)
    monkeypatch.setattr(worker_module.PocVerifier,'verify_standing',forbidden)
    asyncio.run(make_worker(store,repo)._execute(store.get_run(run['id'])))
    result=store.get_run(run['id'])
    assert result['status']=='paused' and result['finished_at'] is None
    assert store.workflow_state(run['id'])['stage']=='poc'
    assert store.workflow_state(run['id'])['budget_pause']['stage']=='poc'
    assert store.get_task_goal(run['id'])['status']=='open'
    assert not store._row('SELECT 1 FROM frozen_run_reports WHERE run_id=?',(run['id'],))
    assert not store.resume_run(run['id'])
    prior=store.execution_summary(run['id'])['run_usage']
    grant(store,run['id'],payload())
    assert store.resume_run(run['id'])
    assert store.execution_summary(run['id'])['run_usage']==prior
    assert store.workflow_state(run['id'])['stage']=='poc'


@pytest.mark.parametrize('stage',['discovery','review'])
def test_other_stage_exhaustion_also_keeps_checkpoint(hosted,monkeypatch,stage):
    store,repo,run=hosted
    add_claim(store,run,1)
    run=enable(store,run)
    workflow=store.workflow_state(run['id']);workflow['stage']=stage
    workflow['limits']=dict(discovery=0,poc=0,review=56) if stage=='discovery' else dict(discovery=55,poc=0,review=1)
    workflow['used']=dict(discovery=0,poc=0,review=0 if stage=='discovery' else 1)
    workflow['source']='explicit'
    store._write('UPDATE run_execution_state SET limits=?,workflow=? WHERE run_id=?',
        (json.dumps(dict(responses=56,tools=200,seconds=3600)),json.dumps(workflow),run['id']))
    async def forbidden(**kwargs):pytest.fail('must pause before another model request')
    monkeypatch.setattr(worker_module,'plan_audit_frontier',forbidden)
    asyncio.run(make_worker(store,repo)._execute(store.get_run(run['id'])))
    assert store.get_run(run['id'])['status']=='paused'
    assert store.workflow_state(run['id'])['stage']==stage
    assert not store._row('SELECT 1 FROM frozen_run_reports WHERE run_id=?',(run['id'],))


def test_global_budget_exhaustion_is_resumable_and_grant_is_atomic_idempotent(hosted):
    store,repo,run=hosted
    run=enable(store,run)
    workflow=store.workflow_state(run['id']);workflow['limits']=dict(discovery=40,poc=8,review=8)
    store._write('UPDATE run_execution_state SET responses_used=56,limits=? WHERE run_id=?',
        (json.dumps(dict(responses=56,tools=200,seconds=3600)),run['id']))
    store._write('UPDATE run_execution_state SET workflow=? WHERE run_id=?',(json.dumps(workflow),run['id']))
    asyncio.run(make_worker(store,repo)._execute(run))
    assert store.get_run(run['id'])['status']=='paused'
    before=store.execution_summary(run['id'])['run_usage']
    value=BudgetGrantRequest(request_id='budget-global',stage='discovery',responses=8).model_dump()
    first=grant(store,run['id'],value)
    assert grant(store,run['id'],value)==first
    assert store.execution_summary(run['id'])['run_limits']['responses']==64
    assert store.execution_summary(run['id'])['run_usage']==before
    with pytest.raises(ValueError,match='不能改变'):
        grant(store,run['id'],{**value,'responses':9})


def test_grant_refuses_spent_transfer_and_zero_phase_funding_without_mutation(hosted):
    store,_,run=hosted;run=enable(store,run)
    pause(store,run['id'],stage='poc');store.quiesce_execution(run['id'])
    workflow=store.workflow_state(run['id']);workflow['stage']='poc';workflow['used']['poc']=workflow['limits']['poc']
    store._write('UPDATE run_execution_state SET workflow=? WHERE run_id=?',(json.dumps(workflow),run['id']))
    before=dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))
    value=BudgetGrantRequest(request_id='invalid-transfer',stage='discovery',transfer_responses=1,transfer_from='poc').model_dump()
    with pytest.raises(ValueError,match='已经消耗'):grant(store,run['id'],value)
    value=BudgetGrantRequest(request_id='only-time-grant',stage='poc',seconds=60).model_dump()
    with pytest.raises(ValueError,match='阶段请求仍已耗尽'):grant(store,run['id'],value)
    assert dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))==before


def test_incremental_policy_carries_accepted_selected_claim_without_repeated_read_review(hosted,monkeypatch):
    from tests import test_review_closure_repair as fixture_module
    original_add=fixture_module.add_claim
    def with_provenance(store,run,*args,**kwargs):
        finding=original_add(store,run,*args,**kwargs)
        assessment={**(finding.get('cvss_assessment') or {}),
            'provenance':dict(finding_id=finding['id'],run_id=run['id'])}
        store._write('UPDATE findings SET cvss_assessment=? WHERE id=?',(json.dumps(assessment),finding['id']))
        return store.get_finding(finding['id'])
    monkeypatch.setattr(fixture_module,'add_claim',with_provenance)
    store,repo,run,batch,values,finding=risk_batch(hosted)
    # Settle both claim and risk under the parent's evidence-aware policy.
    accepted=decisions(batch,'accept')
    values=[a if item['kind']=='finding' else old for item,a,old in zip(batch['items'],accepted,values)]
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='核对当前冻结源码与目标关系后接受结论。',review_batch_id=batch['id'],review_decisions=values)
    finish(store,run)
    child=store.create_continuation(run['id'],request(mode='audit',finding_ids=[finding['id']]))
    records=store.attach_final_decisions(child['id'],store.list_findings(child['id']))
    entries,_=canonical_groups(records)
    assert entries[0]['final_disposition']=='accepted'
    assert entries[0]['final_batch_review']['inherited_from_run_id']==run['id']
    before=next(i for i in store._review_candidates(child['id'],'final') if i['kind']=='finding')
    # The worker-reference navigation set is not a material claim change.
    from audit.review_store import finding_fact_revision
    entry=canonical_groups(store._review_records(child['id'],store.list_findings(child['id'])))[0][0]
    raw=store.list_findings(child['id'])[0]
    assert finding_fact_revision(entry,raw,[dict(task_key='new-reader',rationale='再次读到相同结论')],task=child['task_spec'])==before['revision']
    store._write("UPDATE findings SET summary='新的源码主张导致原结论发生实质变化' WHERE id=?",(raw['id'],))
    assert any(i['kind']=='finding' for b in store.review_batches_pending(child['id'],'final',repo) for i in b)


def test_budget_http_grant_retries_do_not_double_charge(hosted,monkeypatch):
    store,_,run=hosted;enable(store,run);pause(store,run['id']);store.quiesce_execution(run['id'])
    calls=[]
    state=SimpleNamespace(store=store,worker=SimpleNamespace(notify=lambda:calls.append('notify')),
                          bus=SimpleNamespace(emit=lambda *args:None))
    monkeypatch.setattr(app_module.app.state,'services',state,raising=False)
    client=TestClient(app_module.app)
    try:
        value=BudgetGrantRequest(request_id='http-grant-test',stage='discovery',responses=8).model_dump()
        first=client.post(f"/api/runs/{run['id']}/budget",json=value)
        second=client.post(f"/api/runs/{run['id']}/budget",json=value)
    finally:client.close()
    assert first.status_code==second.status_code==200,first.text
    assert second.json()['run_limits']['responses']==store.execution_summary(run['id'])['run_limits']['responses']
    assert calls==['notify']


def test_policy_upgrade_preserves_usage_rejections_and_existing_final_reviews(hosted):
    from audit.checkpoint_upgrade import apply
    store,repo,run,batch,values,finding=risk_batch(hosted)
    accepted=decisions(batch,'accept')
    values=[a if item['kind']=='finding' else old for item,a,old in zip(batch['items'],accepted,values)]
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='既有结论的真实证据仍支持原判决。',review_batch_id=batch['id'],review_decisions=values)
    item=next(i for i in store._review_candidates(run['id'],'final') if i['kind']=='finding')
    store._write("INSERT INTO audit_review_allowances VALUES(?, 'final',?,?,2,?, 'contract:focus',2,'same_error')",
        (run['id'],item['item_id'],item['revision'],json.dumps({'contract:focus':2})))
    store.request_pause(run['id']);store.quiesce_execution(run['id'])
    usage=store.execution_summary(run['id'])['run_usage']
    upgraded=apply(store,run['id'])
    assert upgraded['allowances_preserved']==1
    assert store.execution_summary(run['id'])['run_usage']==usage
    current=next(i for i in store._review_candidates(run['id'],'final') if i['kind']=='finding')
    allowance=store.review_allowances(run['id'],'final')[(current['item_id'],current['revision'])]
    assert allowance['publications']==2 and allowance['consecutive']==2 and allowance['exhausted']=='same_error'
    assert canonical_groups(store.attach_final_decisions(run['id'],store.list_findings(run['id'])))[0][0]['final_disposition']=='accepted'
    assert apply(store,run['id'])==upgraded
    assert not store.frozen_report(run['id'])


def test_covered_direction_keeps_host_settlement_after_id_remapping(hosted):
    from audit.exhaustive import fingerprint
    store,_,run,_,_,finding=risk_batch(hosted)
    direction=completed_task_with_direction(store,run)
    records=store._audit_direction_records(run['id'])
    records[direction['id']].update(state='skipped',triage=dict(outcome='covered',
        finding_refs=[dict(id=finding['id'],fingerprint=fingerprint(dict(store._row('SELECT * FROM findings WHERE id=?',(finding['id'],)))))]))
    store._persist_audit_directions_tx(run['id'],records)
    finish(store,run)
    child=store.create_continuation(run['id'],request(mode='audit'))
    record=store._audit_direction_records(child['id'])[direction['id']]
    assert record['state']=='skipped' and record['triage']['outcome']=='covered'
    assert record['triage']['finding_refs'][0]['id']!=finding['id']


def test_retest_keeps_unchanged_accepted_peer_and_only_new_verification_is_reviewed(hosted):
    store,repo,run,_,original,first=risk_batch(hosted)
    second=add_claim(store,run,2)
    store._write('UPDATE findings SET primary_location=?,evidence=? WHERE id=?',
        (json.dumps(first['primary_location']),json.dumps(first['evidence']),second['id']))
    # risk_batch prepared a lease before the second fixture claim existed.
    # Retire that unused fixture lease so both claims enter this judgment.
    store._write("UPDATE audit_review_batches SET status='stale' WHERE run_id=? AND status='pending'",(run['id'],))
    batch=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    values=decisions(batch,'accept')
    for item,value in zip(batch['items'],values):
        if item['kind']=='risk':
            old=next(d for d in original if d['item_id']==item['item_id'])
            value.update(old);value['revision']=item['revision']
        else:
            value['comparison_assessments']=[dict(item_id=p['item_id'],relation='distinct',rationale='这两项追踪不同参数输入及独立业务前提，使用明确对照保留独立结论。') for p in item['payload']['comparison_candidates']]
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='对关联候选明确完成独立根因判读。',review_batch_id=batch['id'],review_decisions=values)
    parent_entries=canonical_groups(store.attach_final_decisions(run['id'],store.list_findings(run['id'])))[0]
    assert all(e['final_disposition']=='accepted' for e in parent_entries),[(e['canonical_id'],e['final_disposition'],e.get('final_batch_review')) for e in parent_entries]
    finish(store,run)
    child=store.create_continuation(run['id'],request(mode='poc_review',finding_ids=[first['id']]))
    copied=store.list_findings(child['id']);refs=child['task_spec']['continuation']['source_refs']
    tested=next(f for f in copied if refs[f['id']]==first['id']);peer=next(f for f in copied if refs[f['id']]==second['id'])
    assert all(e['final_disposition']=='accepted' for e in canonical_groups(store.attach_final_decisions(child['id'],copied))[0]),child['task_spec']['continuation']['review_reuse']
    from tests.test_poc_store import record
    store.record_automatic_verification(record(tested))
    pending=[i for b in store.review_batches_pending(child['id'],'final',repo) for i in b]
    assert [i['finding_id'] for i in pending if i['kind']=='finding']==[tested['id']]
    assert not any(i['kind']=='risk' for i in pending)
    entries=canonical_groups(store.attach_final_decisions(child['id'],store.list_findings(child['id'])))[0]
    assert next(e for e in entries if e['frozen_claim']['finding_id']==peer['id'])['final_disposition']=='accepted'


def test_explicit_phase_grant_can_run_even_if_later_review_estimate_needs_more(hosted):
    store,repo,run=hosted;add_claim(store,run,1);enable(store,run)
    workflow=store.workflow_state(run['id'])
    workflow.update(source='explicit',stage='discovery',limits=dict(discovery=40,poc=8,review=8),
                    used=dict(discovery=0,poc=0,review=0),poc_reserved_seconds=0)
    store._write('UPDATE run_execution_state SET workflow=?,limits=? WHERE run_id=?',
        (json.dumps(workflow),json.dumps(dict(responses=56,tools=200,seconds=3600)),run['id']))
    state=store.refresh_review_reserve(run['id'],repo,additional_workers=2)
    assert state['remaining']['discovery']==40
    assert state['review_reserve']['funded'] is False
    assert state['review_reserve']['upstream_allowed'] is True
    assert sum(state['limits'].values())==56
