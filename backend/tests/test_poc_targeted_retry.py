import json

import pytest

from audit.poc_retry import requeue
from tests.test_poc_store import state,record  # noqa: F401


def failed(state,*,with_jobs=True):
    store,run,finding=state
    claim=store.claim_poc_attempt(run['id'],finding,'target',run['execution_epoch'])
    store.start_poc_attempt(claim['key'],run['execution_epoch'])
    value=record(finding,status='inconclusive')
    jobs=[dict(job_id='done',context_id='ctx',result=dict(status='finished',exit_code=0))] if with_jobs else []
    value['agent'].update(context_id='ctx',reason='sdk_api_error',jobs=[j['job_id'] for j in jobs],job_results=jobs)
    assert store.record_automatic_verification_guarded(value,attempt_key=claim['key'],epoch=run['execution_epoch'])
    store.append_event(run['id'],None,'poc_context_closed',dict(finding_id=finding['id'],context_id='ctx',state='closed',active=0,pending_jobs=0))
    store.request_pause(run['id']);store.quiesce_execution(run['id'])
    return store,run,finding,claim,value


def test_targeted_retry_preserves_previous_jobs_verdict_and_global_budget(state):
    store,run,f,claim,value=failed(state)
    before=dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))
    result=requeue(store,run['id'],[f['id']],request_id='explicit-retry')
    assert result['previous_attempts'][0]['known_terminal_jobs']==['done']
    assert requeue(store,run['id'],[f['id']],request_id='explicit-retry')==result
    assert dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))==before
    assert store.list_verifications(f['id'])[0]['id']==value['id']
    assert store.resume_run(run['id']);resumed=store.claim_next_run()
    assert store.claim_poc_attempt(run['id'],store.get_finding(f['id']),'target',resumed['execution_epoch'])['claimed']


@pytest.mark.parametrize('change',['unknown','unfinished','context','revision','active','confirmed'])
def test_targeted_retry_rejects_unaccounted_jobs_and_unrelated_or_active_work(state,change):
    store,run,f,claim,value=failed(state)
    if change=='unknown':store._write("UPDATE poc_attempts SET runner_job_id='lost' WHERE key=?",(claim['key'],))
    elif change=='unfinished':
        value['agent']['job_results'][0]['result']['status']='running'
        store._write('UPDATE verifications SET agent=? WHERE id=?',(json.dumps(value['agent']),value['id']))
    elif change=='context':store._write("DELETE FROM events WHERE kind='poc_context_closed'")
    elif change=='revision':store._write('UPDATE findings SET revision=revision+1 WHERE id=?',(f['id'],))
    elif change=='active':store._write("UPDATE runs SET status='running' WHERE id=?",(run['id'],))
    else:store._write("UPDATE findings SET verification_status='verified' WHERE id=?",(f['id'],))
    with pytest.raises(ValueError):requeue(store,run['id'],[f['id']],request_id='explicit-retry')
    assert store._row('SELECT state FROM poc_attempts WHERE key=?',(claim['key'],))[0]=='completed'
