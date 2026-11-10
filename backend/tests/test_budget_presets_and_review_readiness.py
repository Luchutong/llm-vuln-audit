"""Simple shared-budget grants cannot bypass unfinished source evidence."""
import asyncio
import json

import pytest
from jsonschema import Draft202012Validator

from audit import worker as worker_module
from audit.budget_checkpoints import grant,pause
from audit.schemas import BudgetGrantRequest,PlannerDecision
from audit.submission import allowed_review_decisions,bind_review_submission,review_schema,review_example
from tests.test_host_queue import hosted,completed_task_with_direction,add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_incremental_budget_checkpoints import enable
from tests.test_goal_tasks import make_worker,proposal


def checkpoint(hosted):
    store,repo,run=hosted;run=enable(store,run)
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='尚有实际源码任务需要完成。',tasks=[proposal('remaining-source')])
    workflow=store.workflow_state(run['id'])
    workflow.update(source='explicit',stage='review',limits=dict(discovery=11,poc=22,review=23),used=dict(discovery=11,poc=22,review=2))
    store._write('UPDATE run_execution_state SET limits=?,workflow=?,responses_used=35,tools_used=34 WHERE run_id=?',
        (json.dumps(dict(responses=56,tools=200,seconds=2810)),json.dumps(workflow),run['id']))
    pause(store,run['id']);store.quiesce_execution(run['id'])
    return store,repo,run


@pytest.mark.parametrize('extra_requests',[0,64,128,256])
def test_auto_grant_resumes_remaining_work_and_reuses_unspent_shared_budget(hosted,extra_requests):
    store,repo,run=checkpoint(hosted)
    prior=store.execution_summary(run['id'])['run_usage']
    value=BudgetGrantRequest(request_id='auto-budget-grant',responses=extra_requests,seconds=1800).model_dump()
    assert value['stage']=='auto'
    result=grant(store,run['id'],value)
    workflow=store.workflow_state(run['id'])
    assert workflow['stage']=='discovery' and workflow['source']=='derived'
    assert workflow['used']==dict(discovery=11,poc=22,review=2)
    assert workflow['remaining']['discovery']==21+extra_requests
    assert sum(workflow['limits'].values())==56+extra_requests
    assert store.execution_summary(run['id'])['run_usage']==prior
    assert grant(store,run['id'],value)==result
    assert store.resume_run(run['id'])


def test_auto_rejects_mixed_manual_transfer_without_changing_legacy_explicit_api():
    with pytest.raises(ValueError,match='无需指定'):
        BudgetGrantRequest(request_id='invalid-transfer',responses=64,transfer_responses=4,transfer_from='review')
    assert BudgetGrantRequest(request_id='legacy-explicit',stage='poc',responses=64).stage=='poc'


@pytest.mark.parametrize('has_receipt',[False,True])
def test_direction_contract_advertises_only_actions_with_existing_receipts(hosted,has_receipt):
    store,repo,run=hosted;enable(store,run)
    direction=completed_task_with_direction(store,run,required=True,explicit_result=has_receipt)
    item=next(i for i in store._review_candidates(run['id'],'final') if i['kind']=='direction')
    context=item['payload']['resolution_context']
    assert context['can_resolve'] is has_receipt
    assert allowed_review_decisions(item,'final')==(['resolve','needs_evidence'] if has_receipt else ['needs_evidence'])
    batch=dict(id='bounded-directions',phase='final',items=[item])
    schema=review_schema(PlannerDecision.model_json_schema(),batch)
    branch=schema['properties']['review_decisions']['items']['anyOf'][0]
    assert set(branch['properties'])=={'item_id','revision','decision','rationale','finding_ids'}
    example=review_example(batch)
    assert 'risk_outcome' not in example['review_decisions'][0]
    assert 'comparison_assessments' not in example['review_decisions'][0]
    Draft202012Validator(schema).validate(bind_review_submission(example,batch))
    if not has_receipt:
        example['review_decisions'][0]['decision']='resolve'
        with pytest.raises(ValueError,match=direction['id']):bind_review_submission(example,batch)
    example['review_decisions'][0].update(decision='needs_evidence',risk_outcome='pending')
    with pytest.raises(ValueError,match='direction 不允许'):bind_review_submission(example,batch)


def test_unread_source_stops_review_before_any_model_call(hosted,monkeypatch):
    store,repo,run=hosted;run=enable(store,run)
    add_claim(store,run,1);completed_task_with_direction(store,run,required=True)
    workflow=store.workflow_state(run['id']);workflow['stage']='review'
    store._write('UPDATE run_execution_state SET workflow=? WHERE run_id=?',(json.dumps(workflow),run['id']))
    async def forbidden(**kwargs):pytest.fail('missing worker evidence is a host prerequisite, not a review model task')
    monkeypatch.setattr(worker_module,'plan_audit_frontier',forbidden)
    asyncio.run(make_worker(store,repo)._execute(store.get_run(run['id'])))
    result=store.get_run(run['id']);summary=result['execution_summary']
    assert result['status']=='paused' and summary['workflow']['stage']=='review'
    assert summary['workflow']['budget_pause']['stage']=='discovery'
    assert summary['stop_reason']['code']=='source_evidence_required'
    assert summary['run_usage']['responses']==0
    assert not store.frozen_report(run['id'])
