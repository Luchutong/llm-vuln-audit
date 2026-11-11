"""Explicit targeted retries of terminal POC failures, preserving every old fact."""
import json


def requeue(store, run_id, finding_ids, *, request_id):
    """Only a quiet checkpoint and a fully accounted, closed context may retry.

    This is an explicit new experiment request, never automatic crash replay.
    Unknown submissions stay blocked; completed jobs and verdicts remain history.
    """
    from .execution_state import stamp
    if not request_id or not finding_ids:raise ValueError('须明确指定重试授权和发现 ID')
    with store._lock:
        store._db.execute('BEGIN IMMEDIATE')
        try:
            prior=store._row("SELECT payload FROM events WHERE run_id=? AND kind='poc_targeted_retry_queued' AND json_extract(payload,'$.request_id')=?",(run_id,request_id))
            if prior:
                result=json.loads(prior[0])
                if result['finding_ids']!=sorted(set(finding_ids)):raise ValueError('同一授权不能更改重试范围')
                store._db.execute('COMMIT');return result
            state=store._row('SELECT r.status,e.phase FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?',(run_id,))
            if not state or state['status']!='paused' or state['phase']!='paused' or run_id in store._active_clocks:
                raise ValueError('重试要求静止的暂停检查点')
            if store._row("SELECT 1 FROM poc_attempts WHERE run_id=? AND state IN ('claimed','running')",(run_id,)):
                raise ValueError('仍有未关闭的 POC 租约')
            queued=[]
            for ident in sorted(set(finding_ids)):
                attempt=store._row('SELECT * FROM poc_attempts WHERE run_id=? AND finding_id=?',(run_id,ident))
                finding=store.get_finding(ident)
                if (not attempt or not finding or finding['run_id']!=run_id
                        or attempt['state'] not in {'completed','interrupted','unavailable'}
                        or finding.get('verification_status') not in {'unverified','inconclusive'}
                        or attempt['finding_revision']!=int(finding.get('revision') or 1)
                        or attempt['revision']!=int(finding.get('project_revision') or finding.get('revision') or 1)):
                    raise ValueError('仅可重试当前版本尚未确定的终态 POC')
                closed=store._row("SELECT payload FROM events WHERE run_id=? AND kind='poc_context_closed' AND json_extract(payload,'$.finding_id')=? AND created_at>=? ORDER BY id DESC LIMIT 1",(run_id,ident,attempt['created_at']))
                closure=json.loads(closed[0]) if closed else {}
                if closure.get('state')!='closed' or closure.get('active')!=0 or closure.get('pending_jobs')!=0:
                    raise ValueError('缺少该次上下文完全关闭的确认')
                verification=next((v for v in finding.get('verifications') or [] if v['id']==attempt['verification_id']),None)
                agent=(verification or {}).get('agent') or {}
                if verification and (verification['status']!='inconclusive' or agent.get('context_id')!=closure.get('context_id')):
                    raise ValueError('已确定结果或上下文不匹配，不能重试')
                jobs={j['job_id']:j for j in agent.get('job_results') or []}
                started=store._rows("SELECT payload FROM events WHERE run_id=? AND kind='poc_job_started' AND json_extract(payload,'$.context_id')=?",(run_id,closure.get('context_id')))
                expected=set(agent.get('jobs') or [])|{json.loads(x[0]).get('job_id') for x in started}
                facts=store._rows("SELECT job_id,result FROM poc_verification_jobs WHERE run_id=? AND finding_id=? AND (verification_id=? OR (verification_id='' AND created_at>=?))",
                                  (run_id,ident,attempt['verification_id'] or '',attempt['created_at']))
                expected.update(x['job_id'] for x in facts)
                if attempt['runner_job_id']:expected.add(attempt['runner_job_id'])
                expected.discard(None)
                for job_id in expected:
                    job=jobs.get(job_id);raw=(job or {}).get('result') or {}
                    if (not job or job.get('context_id')!=closure.get('context_id')
                            or raw.get('status') not in {'finished','failed','cancelled','timed_out'}):
                        raise ValueError('存在结果未知或未终止的原实验，禁止重放')
                prior_retry=store._row("SELECT 1 FROM events WHERE run_id=? AND kind='poc_targeted_retry_queued' AND EXISTS(SELECT 1 FROM json_each(json_extract(events.payload,'$.finding_ids')) WHERE value=?)",(run_id,ident))
                if prior_retry:raise ValueError('该发现已有一次定向重试授权，不能反复刷新额度')
                queued.append(dict(attempt=dict(attempt),context_id=closure['context_id'],known_terminal_jobs=sorted(expected)))
            for item in queued:
                store._db.execute("UPDATE poc_attempts SET state='claimed',verification_id=NULL,runner_job_id=NULL,updated_at=? WHERE key=?",(stamp(),item['attempt']['key']))
            result=dict(request_id=request_id,finding_ids=sorted(set(finding_ids)),previous_attempts=queued,
                        at=stamp(),added_budget=dict(responses=0,tools=0,seconds=0))
            store.append_event(run_id,None,'poc_targeted_retry_queued',result)
            store._db.execute('COMMIT');return result
        except BaseException:
            if store._db.in_transaction:store._db.execute('ROLLBACK')
            raise
