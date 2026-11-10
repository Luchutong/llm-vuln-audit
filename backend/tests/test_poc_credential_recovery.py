"""Credential recovery preserves failures and never replays a submitted experiment."""
import json

import pytest

from tests.test_poc_store import state, record  # noqa: F401


def failed(store,run,finding):
    claim=store.claim_poc_attempt(run['id'],finding,'target',run['execution_epoch'])
    assert store.start_poc_attempt(claim['key'],run['execution_epoch'])
    value=record(finding,status='inconclusive');value['agent'].update(context_id='ctx',reason='sdk_api_error',jobs=[],job_results=[])
    assert store.record_automatic_verification_guarded(value,attempt_key=claim['key'],epoch=run['execution_epoch'])
    store.append_event(run['id'],None,'poc_context_closed',dict(context_id='ctx',state='closed',active=0,pending_jobs=0))
    store.request_pause(run['id']);store.quiesce_execution(run['id'])
    return claim,value


def test_one_explicit_zero_submission_retry_keeps_history_and_usage(state):
    store,run,finding=state;claim,value=failed(store,run,finding)
    # Carried evidence from an earlier verification is history, not a new submission.
    store._upsert_poc_job_fact(dict(store._row('SELECT * FROM poc_attempts WHERE key=?',(claim['key'],))),
        dict(job_id='historical',result={}),verification_id='old-inherited-verification')
    before=dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))
    queued=store.requeue_unstarted_poc_attempts(run['id'],[finding['id']])
    assert queued[0]['previous_verification_id']==value['id']
    assert store.list_verifications(finding['id'])[0]['status']=='inconclusive'
    assert dict(store._row('SELECT * FROM run_execution_state WHERE run_id=?',(run['id'],)))==before
    assert store.resume_run(run['id']);resumed=store.claim_next_run()
    retried=store.claim_poc_attempt(run['id'],store.get_finding(finding['id']),'target',resumed['execution_epoch'])
    assert retried['claimed'] and retried['key']==claim['key']
    assert store.start_poc_attempt(claim['key'],resumed['execution_epoch'])
    second={**value,'id':'second'}
    assert store.record_automatic_verification_guarded(second,attempt_key=claim['key'],epoch=resumed['execution_epoch'])
    store.request_pause(run['id']);store.quiesce_execution(run['id'])
    with pytest.raises(ValueError,match='一次'):store.requeue_unstarted_poc_attempts(run['id'],[finding['id']])
    assert len(store.list_verifications(finding['id']))==2
    store.requeue_unstarted_poc_attempts(run['id'],[finding['id']],credential_revision='a'*64)
    assert store.resume_run(run['id']);resumed=store.claim_next_run()
    assert store.claim_poc_attempt(run['id'],store.get_finding(finding['id']),'target',resumed['execution_epoch'])['claimed']
    assert store.start_poc_attempt(claim['key'],resumed['execution_epoch'])
    assert store.record_automatic_verification_guarded({**value,'id':'third'},attempt_key=claim['key'],epoch=resumed['execution_epoch'])
    store.request_pause(run['id']);store.quiesce_execution(run['id'])
    for revision in ['a'*64,'b'*64]:
        with pytest.raises(ValueError,match='最多两次'):
            store.requeue_unstarted_poc_attempts(run['id'],[finding['id']],credential_revision=revision)
    assert len(store.list_verifications(finding['id']))==3


def test_pause_recovery_requires_evidence_of_pause_then_interruption(state):
    store,run,finding=state;claim,value=failed(store,run,finding)
    with pytest.raises(ValueError,match='缺少'):
        store.requeue_unstarted_poc_attempts(run['id'],[finding['id']],recovery_reason='pause')
    store.append_event(run['id'],None,'run_pause_requested',dict(reason='user_paused'))
    store.append_event(run['id'],None,'poc_runtime_error',dict(context_id='ctx',http_status=401,code='sdk_api_error'))
    queued=store.requeue_unstarted_poc_attempts(run['id'],[finding['id']],recovery_reason='pause')
    assert queued[0]['reason']=='pause_interruption_zero_submissions'
    assert store.list_verifications(finding['id'])[0]['id']==value['id']
    assert store._row('SELECT state FROM poc_attempts WHERE key=?',(claim['key'],))[0]=='claimed'


@pytest.mark.parametrize('change',['unclosed','pending','job_id','job_fact','submitted','verified'])
def test_recovery_rejects_unsafe_or_inapplicable_attempts(state,change):
    store,run,finding=state;claim,value=failed(store,run,finding)
    if change=='unclosed':store._write("DELETE FROM events WHERE kind='poc_context_closed'")
    elif change=='pending':
        store.append_event(run['id'],None,'poc_context_closed',dict(context_id='ctx',state='closed',active=0,pending_jobs=1))
    elif change=='job_id':store._write("UPDATE poc_attempts SET runner_job_id='unknown' WHERE key=?",(claim['key'],))
    elif change=='job_fact':
        store._upsert_poc_job_fact(dict(store._row('SELECT * FROM poc_attempts WHERE key=?',(claim['key'],))),dict(job_id='actual',result={}))
    elif change=='submitted':store.append_event(run['id'],None,'poc_job_started',dict(finding_id=finding['id']))
    else:store._write("UPDATE findings SET verification_status='verified' WHERE id=?",(finding['id'],))
    with pytest.raises(ValueError):store.requeue_unstarted_poc_attempts(run['id'],[finding['id']])
    assert store._row('SELECT state FROM poc_attempts WHERE key=?',(claim['key'],))[0]=='completed'
