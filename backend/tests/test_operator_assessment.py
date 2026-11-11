import copy

import pytest

from audit.closure_checkpoint import repair
from audit.operator_assessment import assess
from tests.test_closure_checkpoint import checkpoint
from tests.test_host_queue import hosted  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_incremental_budget_checkpoints import enable


def prepared(hosted,monkeypatch):
    store,run,d,manifest=checkpoint(hosted,monkeypatch)
    enable(store,run,completion_recovery_policy='assigned-gaps-v1',role_policy='worker-evidence-v2')
    new=repair(store,run['id'],manifest)
    task=next(t for t in store.list_tasks(run['id'],include_attempts=False) if t['task_key']==new['tasks'][0]['task_key'])
    proof=dict(basis='not_applicable',rationale='此测试方向限于入口是否实现记住我令牌；入口仅将路径参数交给文件处理，未实现该类认证令牌，不据此排除文件读取风险。',
               evidence=[dict(path='public/index.php',start_line=1,end_line=4)])
    result=dict(outcome='no_evidence',summary='核读入口后仅排除本次独立令牌方向',reasoning=proof['rationale'],
                findings=[],finding_references=[],observations=[],candidate_updates=[],remaining_work=[],
                direction_results=[dict(direction_id=d['id'],outcome='no_evidence',rationale=proof['rationale'],disproof=proof)])
    return store,run,task,result


def test_operator_uses_original_evidence_gates_and_charges_actual_reads(hosted,monkeypatch):
    store,run,task,result=prepared(hosted,monkeypatch)
    before=store.execution_summary(run['id']);original=store.resolve_task_attempt
    def fenced(*args,**kwargs):
        assert not store.resume_run(run['id'])
        return original(*args,**kwargs)
    monkeypatch.setattr(store,'resolve_task_attempt',fenced)
    done=assess(store,hosted[1],run['id'],task['id'],result,actor='test-operator')
    assert done['state']=='completed' and done['attempts']==1
    assert done['result']['assessment_source']=='operator' and done['result']['assessment_actor']=='test-operator'
    after=store.execution_summary(run['id'])
    assert before['run_limits']==after['run_limits']
    assert before['run_usage']['responses']==after['run_usage']['responses']
    assert after['run_usage']['tools']==before['run_usage']['tools']+1
    assert store.list_task_attempts(task['id'])[-1]['seen']==[dict(path='public/index.php',start_line=1,end_line=4)]


def test_operator_cannot_publish_unread_source_or_omit_the_assigned_direction(hosted,monkeypatch):
    store,run,task,result=prepared(hosted,monkeypatch)
    missing=copy.deepcopy(result);missing['direction_results']=[]
    with pytest.raises(ValueError,match='方向 ID'):assess(store,hosted[1],run['id'],task['id'],missing,actor='test')
    result['direction_results'][0]['disproof']['evidence'][0]['path']='src/files.php'
    with pytest.raises(ValueError,match='反证'):assess(store,hosted[1],run['id'],task['id'],result,actor='test')
    assert store.get_planner_task(task['id'])['state']=='ready'
    assert store.get_planner_task(task['id'])['attempts']==0
