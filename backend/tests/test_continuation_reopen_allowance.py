"""New audit budgets bound corrections per run without deleting historical revisions."""
import json
from types import SimpleNamespace

import pytest

from audit.agent import _check_reopen, ModelRetry
from tests.test_host_queue import hosted  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_run_continuations import request, finish
from tests.test_goal_tasks import proposal


@pytest.mark.parametrize('legacy_checkpoint',[False,True])
def test_explicit_audit_has_bounded_new_reopens_with_history_intact(hosted,legacy_checkpoint):
    store,_,parent=hosted
    key='legacy-blocked'
    plan=store.begin_planner_round(parent['id'],store.get_planner_session(parent['id'])['session_id'])
    store.finish_planner_round(parent['id'],plan['id'],goal_state='continue',basis_summary='派发需要继续核对的源码任务',tasks=[proposal(key)])
    store._write("UPDATE planner_tasks SET state='blocked',revisions=2 WHERE run_id=?",(parent['id'],))
    finish(store,parent)
    child=store.create_continuation(parent['id'],request(mode='audit'))
    assert child['task_spec']['continuation']['task_reopen_baselines']=={key:2}
    if legacy_checkpoint:
        spec=child['task_spec'];spec['continuation'].pop('task_reopen_baselines')
        store._write('UPDATE runs SET task_spec=? WHERE id=?',(json.dumps(spec),child['id']))
    assert store.task_reopen_baselines(child['id'])=={key:2}
    run=store.claim_next_run();assert run['id']==child['id']
    for used in range(3):
        store._write("UPDATE planner_tasks SET state='blocked' WHERE run_id=?",(child['id'],))
        task=next(t for t in store.list_planner_context(child['id'])['tasks'] if t['task_key']==key)
        assert task['revisions']==2+used and task['reopens_this_run']==used
        update=dict(task_key=key,action='reopen',rationale_summary='补充已读取的新证据，缩小到尚未结算的具体操作。')
        plan=store.begin_planner_round(child['id'],store.get_planner_session(child['id'])['session_id'])
        if used<2:
            _check_reopen(SimpleNamespace(**update),task,'blocked',task_limit=2,run_left=16-used,run_limit=16)
            store.finish_planner_round(child['id'],plan['id'],goal_state='continue',basis_summary='对未决操作进行有界修正',updates=[update])
        else:
            with pytest.raises(ModelRetry,match='本轮运行已经重开 2'):
                _check_reopen(SimpleNamespace(**update),task,'blocked',task_limit=2,run_left=14,run_limit=16)
            with pytest.raises(ValueError,match='reopen allowance exhausted'):
                store.finish_planner_round(child['id'],plan['id'],goal_state='continue',basis_summary='不能刷新跨回合额度',updates=[update])
    assert store._row('SELECT revisions FROM planner_tasks WHERE run_id=?',(parent['id'],))[0]==2
    assert store._row('SELECT revisions FROM planner_tasks WHERE run_id=?',(child['id'],))[0]==4


def test_ordinary_run_keeps_existing_task_reopen_limit(hosted):
    store,_,run=hosted
    assert store.task_reopen_baselines(run['id'])=={}
    with pytest.raises(ModelRetry,match='已经重开 2'):
        _check_reopen(SimpleNamespace(task_key='ordinary'),dict(revisions=2),'blocked',task_limit=2,run_left=16,run_limit=16)


def test_quiescent_repair_restores_only_unused_transfer_without_renewing_cost_or_allowances(hosted):
    store,_,parent=hosted
    plan=store.begin_planner_round(parent['id'],store.get_planner_session(parent['id'])['session_id'])
    store.finish_planner_round(parent['id'],plan['id'],goal_state='continue',basis_summary='保留被历史上限阻塞的具体操作',tasks=[proposal('blocked')])
    store._write("UPDATE planner_tasks SET state='blocked',revisions=2 WHERE run_id=?",(parent['id'],))
    finish(store,parent)
    child=store.create_continuation(parent['id'],request(mode='audit'));rid=child['id']
    store.claim_next_run()
    store._write("UPDATE planner_tasks SET state='blocked' WHERE run_id=?",(rid,))
    store.set_workflow_stage(rid,'poc',reason=dict(code='blocker_unresolved'),transfer_unused=True)
    store.request_pause(rid);store.quiesce_execution(rid)
    store._write('UPDATE run_execution_state SET responses_used=7,tools_used=4,active_elapsed_ms=12000 WHERE run_id=?',(rid,))
    store._write("INSERT INTO audit_review_allowances(run_id,phase,item_id,revision,publications,errors,exhausted) VALUES(?,'final','r','v',3,'{}','publication_limit')",(rid,))
    before=dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(rid,)))
    allowance=dict(store._row('SELECT * FROM audit_review_allowances WHERE run_id=?',(rid,)))
    after=store.repair_paused_continuation_frontier(rid)
    assert after['stage']=='discovery'
    old=json.loads(before['workflow'])
    assert sum(after['limits'].values())==sum(old['limits'].values())
    assert after['used']==old['used'] and after['limits']['review']==old['limits']['review']
    assert after['limits']['discovery']-old['limits']['discovery']==old['transferred']
    raw=store._row('SELECT * FROM run_execution_state WHERE run_id=?',(rid,))
    assert all(raw[k]==before[k] for k in ['responses_used','tools_used','active_elapsed_ms','limits','claim_epoch','poc_state'])
    assert dict(store._row('SELECT * FROM audit_review_allowances WHERE run_id=?',(rid,)))==allowance
    with pytest.raises(ValueError):store.repair_paused_continuation_frontier(rid)
    assert store.resume_run(rid)


def test_frontier_repair_rejects_non_quiescent_and_unrelated_runs(hosted):
    store,_,run=hosted
    with pytest.raises(ValueError,match='静止'):store.repair_paused_continuation_frontier(run['id'])
    store.request_pause(run['id']);store.quiesce_execution(run['id'])
    with pytest.raises(ValueError,match='历史重开'):store.repair_paused_continuation_frontier(run['id'])
