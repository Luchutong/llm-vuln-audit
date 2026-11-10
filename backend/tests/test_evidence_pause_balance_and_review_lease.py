"""A source gap is not spent credit, and a review owns its precise phase lease."""
import asyncio
import json

import pytest

from audit import agent
from audit.budget_checkpoints import pause
from audit.runtime import AgentPolicy,StopAudit
from tests.test_host_queue import hosted,add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_incremental_budget_checkpoints import enable
from tests.test_run_continuations import decisions
from tests.code_model import ModelFactory,CONFIG
from tests.test_goal_tasks import proposal


def test_source_gap_resumes_with_remaining_balance_without_grant_or_counter_reset(hosted):
    store,_,run=hosted;enable(store,run)
    workflow=store.workflow_state(run['id'])
    workflow.update(stage='poc',limits=dict(discovery=32,poc=216,review=36),used=dict(discovery=32,poc=44,review=17),transferred=172)
    limits=dict(responses=284,tools=5075,seconds=10110)
    store._write('UPDATE run_execution_state SET limits=?,workflow=?,responses_used=93,tools_used=69 WHERE run_id=?',
        (json.dumps(limits),json.dumps(workflow),run['id']))
    store._write("INSERT INTO audit_review_allowances VALUES(?,'final','item','version',2,?, 'contract:focus',2,'same_error')",
        (run['id'],json.dumps({'contract:focus':2})))
    pause(store,run['id'],stage='discovery',reason='source_evidence_required');store.quiesce_execution(run['id'])
    prior=store.execution_summary(run['id'])['run_usage'];allowances=store.review_allowances(run['id'],'final')
    assert store.resume_run(run['id'])
    current=store.execution_summary(run['id'])
    assert current['run_limits']==limits and current['run_usage']==prior
    assert current['workflow']['stage']=='discovery' and current['workflow']['remaining']['discovery']==191
    assert sum(current['workflow']['limits'].values())==284
    assert store.review_allowances(run['id'],'final')==allowances
    assert not store._row("SELECT 1 FROM events WHERE run_id=? AND kind='run_budget_granted'",(run['id'],))
    event=json.loads(store._row("SELECT payload FROM events WHERE run_id=? AND kind='run_balance_reused'",(run['id'],))[0])
    assert event['added_budget']==dict(responses=0,tools=0,seconds=0)
    assert not store.resume_run(run['id'])


def test_integration_lease_is_not_shadowed_by_an_older_final_lease(hosted):
    store,repo,run=hosted;finding=add_claim(store,run,1)
    store.append_event(run['id'],None,'finding_duplicate_candidate',dict(finding_id=finding['id'],candidate_ids=[]))
    old=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    store._write('UPDATE audit_review_batches SET epoch=epoch-1 WHERE id=?',(old['id'],))
    new=store.prepare_review_batch(run['id'],'integration',run['execution_epoch'],repo)
    assert store.active_review_batch(run['id'])['id']==old['id']
    assert store.active_review_batch(run['id'],'integration')['id']==new['id']
    store.reserve_review_publication(run['id'],new['id'])
    with pytest.raises(StopAudit,match='租约'):
        store.reserve_review_publication(run['id'],old['id'])
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='仅提交本次实际领取的 integration 批次。',
        review_batch_id=new['id'],review_decisions=decisions(new,'retain'))
    assert store._row('SELECT status FROM audit_review_batches WHERE id=?',(new['id'],))[0]=='completed'
    assert store._row('SELECT status FROM audit_review_batches WHERE id=?',(old['id'],))[0]=='pending'


def test_source_planner_does_not_spend_corrections_on_uncommittable_dynamic_reviews(hosted,monkeypatch):
    store,repo,run=hosted;finding=add_claim(store,run,1,verified=True)
    context=store.list_planner_context(run['id']);context['review_batch']=None
    value=dict(goal_state='continue',basis_summary='继续读取源码，动态观测留给后续独立终审。',tasks=[proposal('next-source')],
        verification_reviews=[dict(finding_id=finding['id'],revision=finding['revision'],
            verification_id=finding['verifications'][0]['id'],decision='confirmed',rationale_summary='普通与攻击观测声称构成对照。')])
    factory=ModelFactory({'planner_publish':[json.dumps(value)]})
    monkeypatch.setattr(agent,'build_code_model',factory);events=[]
    result=asyncio.run(agent.plan_audit_frontier(project_map=store.get_project_map(run['id']),run_context=context,
        task=run['task_spec'],round_no=1,config=CONFIG,budgets=dict(responses=3,tools=0,seconds=10),
        policy=AgentPolicy(planner_explore_responses=0,request_seconds=.5),repository=repo,snapshot_id=run['snapshot_id'],
        allowed_paths=set(run['scope']),pins=store,run_id=run['id'],on_event=events.append))
    assert result['decision'],(result,[e.get('hint') for e in events if e.get('kind')=='agent_output_rejected'])
    assert not result['decision'].get('verification_reviews')
    assert result['usage']['requests']==1
    assert any(e.get('reason')=='dynamic_review_requires_final_batch' for e in events)
    assert store.list_verification_reviews(run['id'])==[]
