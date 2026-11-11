import json

import pytest

from audit.budget_checkpoints import pause
from audit.closure_checkpoint import repair
from audit.schemas import PlannerDecision
from audit.task_contract import planner_schema
from tests.test_host_queue import hosted,completed_task_with_direction  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_incremental_budget_checkpoints import enable
from tests.test_goal_tasks import proposal
from jsonschema import Draft202012Validator


def checkpoint(hosted,monkeypatch):
    store,repo,run=hosted
    enable(store,run,completion_recovery_policy='assigned-gaps-v1')
    d=completed_task_with_direction(store,run)
    records=store._audit_direction_records(run['id']);records[d['id']].update(state='pending',assigned_task_key=None)
    store._persist_audit_directions_tx(run['id'],records)
    monkeypatch.setattr(store,'coverage_review',lambda *args,**kwargs:dict(complete=True,pending_total=0))
    pause(store,run['id'],stage='discovery',reason='source_evidence_required');store.quiesce_execution(run['id'])
    manifest=[dict(title='补齐该方向取证结果',objective='仅结算原有方向并复用已有结论',direction_ids=[d['id']],source_paths=['public/index.php'])]
    return store,run,d,manifest


def test_checkpoint_repair_preserves_caps_history_and_uses_exact_direction_ids(hosted,monkeypatch):
    store,run,d,manifest=checkpoint(hosted,monkeypatch)
    execution=dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))
    old_tasks=[dict(row) for row in store._rows('SELECT * FROM planner_tasks WHERE run_id=?',(run['id'],))]
    attempts=[dict(row) for row in store._rows('SELECT * FROM planner_task_attempts WHERE run_id=?',(run['id'],))]
    result=repair(store,run['id'],manifest)
    assert result['added_budget']==dict(responses=0,tools=0,seconds=0)
    assert repair(store,run['id'],manifest)==result
    after=dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))
    assert all(after[k]==execution[k] for k in ['limits','responses_used','tools_used','active_elapsed_ms'])
    assert [dict(row) for row in store._rows('SELECT * FROM planner_task_attempts WHERE run_id=?',(run['id'],))]==attempts
    current=store._audit_direction_records(run['id'])[d['id']]
    assert current['assigned_task_key']==result['tasks'][0]['task_key'] and current['state']=='assigned'
    for old in old_tasks:
        new=dict(store._row('SELECT * FROM planner_tasks WHERE id=?',(old['id'],)))
        assert all(new[k]==old[k] for k in old if k!='result')
    assert len(store.list_tasks(run['id']))==len(old_tasks)+1
    assert store.worker_candidate_gaps(run['id'])==[]


@pytest.mark.parametrize('bad',['omitted','repeated','outside','active'])
def test_bad_checkpoint_manifest_is_atomic(hosted,monkeypatch,bad):
    store,run,d,manifest=checkpoint(hosted,monkeypatch)
    before=store._row('SELECT count(*) FROM planner_tasks WHERE run_id=?',(run['id'],))[0]
    if bad=='omitted':manifest=[]
    elif bad=='repeated':manifest=manifest*2
    elif bad=='outside':manifest[0]['source_paths']=['absent.php']
    else:store._write("UPDATE runs SET status='running' WHERE id=?",(run['id'],))
    with pytest.raises(ValueError):repair(store,run['id'],manifest)
    assert store._row('SELECT count(*) FROM planner_tasks WHERE run_id=?',(run['id'],))[0]==before
    assert store._audit_direction_records(run['id'])[d['id']]['state']=='pending'


def test_closure_planner_cannot_dispatch_an_unbound_duplicate(hosted,monkeypatch):
    store,run,d,manifest=checkpoint(hosted,monkeypatch)
    assert store.resume_run(run['id']);store.claim_next_run()
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    with pytest.raises(ValueError,match='绑定未决 direction_ids'):
        store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='读取已有根因的同义任务',tasks=[proposal('new-name')])
    schema=planner_schema(PlannerDecision.model_json_schema(),store.get_project_map(run['id']),store.list_tasks(run['id']),closure_direction_ids=[d['id']])
    data=dict(basis_summary='仅结算当前未决方向',tasks=[proposal('bound')]);check=Draft202012Validator(schema)
    assert not check.is_valid(data)
    data['tasks'][0]['direction_ids']=[d['id']]
    assert check.is_valid(data)


def test_quiet_operator_plan_is_serialized_and_uses_existing_reopen_contract(hosted,monkeypatch):
    store,run,d,manifest=checkpoint(hosted,monkeypatch)
    before=dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))
    session=store.get_planner_session(run['id'])['session_id']
    assert store.begin_planner_round(run['id'],session) is None
    plan=store.begin_planner_round(run['id'],session,checkpoint_repair=True)
    assert plan and store.get_run(run['id'])['status']=='paused'
    assert store.begin_planner_round(run['id'],session,checkpoint_repair=True) is None
    assert dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))==before
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='仅记录人工核对，未增加任何预算')


def test_worker_direction_schema_requires_disproof_and_the_assigned_id():
    from audit.agent import _worker_publication_schema
    task=dict(role_policy='worker-evidence-v2',assigned_direction_ids=['dir_'+'a'*32])
    schema=_worker_publication_schema(2,task=task)
    fragment={'$defs':schema['$defs'],'$ref':'#/$defs/WorkerDirectionResult'}
    check=Draft202012Validator(fragment)
    value=dict(direction_id=task['assigned_direction_ids'][0],outcome='no_evidence',rationale='原始源码显示没有该方向假设的实现')
    assert not check.is_valid(value)
    value['disproof']=dict(basis='not_applicable',rationale='已读实现未使用该类独立令牌',evidence=[dict(path='auth.php',start_line=1,end_line=5)])
    assert check.is_valid(value)
    value['direction_id']='dir_'+'b'*32
    assert not check.is_valid(value)


def test_supported_direction_review_requires_explicit_finding_references():
    from audit.submission import review_schema,bind_review_submission
    item=dict(kind='direction',item_id='dir_'+'a'*32,revision='version',payload=dict(resolution_context=dict(
        requirement='required',can_resolve=True,worker_results=[dict(outcome='supported')],eligible_finding_ids=['actual-finding'])))
    batch=dict(id='batch',phase='integration',items=[item])
    schema=review_schema(PlannerDecision.model_json_schema(),batch)
    value=dict(basis_summary='依据同一方向的源码与有效结论完成复核',review_decisions=[dict(
        item_id=item['item_id'],revision='version',decision='resolve',rationale='已复核此方向真实输入与操作，并与既有根因一致')])
    assert not Draft202012Validator(schema).is_valid(value)
    with pytest.raises(ValueError,match=item['item_id']):bind_review_submission(value,batch)
    value['review_decisions'][0]['finding_ids']=['actual-finding']
    assert Draft202012Validator(schema).is_valid(value)
    assert bind_review_submission(value,batch)['review_decisions'][0]['finding_ids']==['actual-finding']


def test_closure_publication_reads_full_direction_records_not_the_summary_object(hosted,monkeypatch):
    import asyncio
    from audit import agent
    from audit.runtime import AgentPolicy
    from tests.code_model import ModelFactory,CONFIG
    store,repo,run=hosted
    enable(store,run,completion_recovery_policy='assigned-gaps-v1')
    d=completed_task_with_direction(store,run,required=True)
    context=store.list_planner_context(run['id']);context.update(review_batch=None,coverage_review=dict(complete=True,pending_total=0))
    assert isinstance(context['directions'],dict)
    task=store.get_run(run['id'])['task_spec']
    value=dict(goal_state='inconclusive',basis_summary='保留当前方向的具体补证需求，本轮不创建同义任务。',tasks=[])
    monkeypatch.setattr(agent,'build_code_model',ModelFactory({'planner_publish':[json.dumps(value)]}))
    result=asyncio.run(agent.plan_audit_frontier(project_map=store.get_project_map(run['id']),run_context=context,
        task=task,round_no=2,config=CONFIG,budgets=dict(responses=3,tools=0,seconds=10),
        policy=AgentPolicy(planner_explore_responses=0,request_seconds=.5),repository=repo,snapshot_id=run['snapshot_id'],
        allowed_paths=set(run['scope']),pins=store,run_id=run['id']))
    assert result['decision'],result
    assert result['usage']['requests']==1
