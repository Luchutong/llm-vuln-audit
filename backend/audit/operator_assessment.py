"""User-authorized source review without an additional model request."""
import json


def assess(store, repository, run_id, task_id, result, *, actor):
    """An operator supplies the judgment; the existing evidence gates still apply."""
    from .execution_state import stamp
    if not actor:raise ValueError('必须记录审查者')
    task=store.get_planner_task(task_id)
    state=store._row('SELECT r.status,r.snapshot_id,e.phase,e.limits,e.tools_used FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?',(run_id,))
    if not task or task['run_id']!=run_id or not state or state['status']!='paused' or state['phase']!='paused':
        raise ValueError('人工补证要求静止暂停检查点')
    if task['state']!='ready' or task['attempts']>=task['max_attempts']:
        raise ValueError('没有可用的原任务尝试')
    ids={d['id'] for d in store.assigned_task_directions(run_id,task['task_key'])}
    returned=[d['direction_id'] for d in result.get('direction_results') or []]
    if not ids or len(returned)!=len(set(returned)) or set(returned)!=ids:
        raise ValueError('必须逐项处理本任务实际分派的方向 ID')
    goal=store.get_task_goal(run_id)
    if goal['status']!='open' or goal['attempts']>=goal['max_total_attempts']:
        raise ValueError('共享尝试额度已耗尽')
    sources=[repository.read_source(state['snapshot_id'],r['path'],r['start_line'],r['end_line'])
             for r in task['context_spec'].get('source_refs') or []]
    seen=[dict(path=s['path'],start_line=s['start_line'],end_line=s['end_line']) for s in sources]
    limits=json.loads(state['limits']);worker='operator:'+actor
    with store._lock:
        store._db.execute('BEGIN IMMEDIATE')
        try:
            current=store._row('SELECT r.status,e.phase,e.tools_used FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?',(run_id,))
            if (current['status']!='paused' or current['phase']!='paused' or run_id in store._active_clocks
                    or store._row("SELECT 1 FROM planner_tasks WHERE run_id=? AND state='running'",(run_id,))):
                raise ValueError('检查点已变化或仍有在途源码任务')
            if limits.get('tools') and current['tools_used']+len(sources)>limits['tools']:
                raise ValueError('原工具预算不足')
            if not store._db.execute("UPDATE planner_tasks SET state='running',claimed_by=?,claimed_at=? WHERE id=? AND state='ready'",(worker,stamp(),task_id)).rowcount:
                raise ValueError('任务已被领取')
            store._db.execute('UPDATE run_execution_state SET tools_used=tools_used+? WHERE run_id=?',(len(sources),run_id))
            store.append_event(run_id,None,'operator_source_review_started',dict(actor=actor,task_id=task_id,source_reads=[dict(**span,sha256=s['sha256']) for span,s in zip(seen,sources)]))
            store._db.execute('COMMIT')
        except BaseException:
            if store._db.in_transaction:store._db.execute('ROLLBACK')
            raise
    try:
        assessment={**result,'terminal_reason':'completed','assessment_source':'operator','assessment_actor':actor}
        resolved=store.resolve_task_attempt(task_id,worker,outcome=result['outcome'],result=assessment,
            usage=dict(requests=0,tool_calls=len(sources),source='operator'),seen=seen,terminal_reason='completed')
        store.append_event(run_id,None,'operator_source_review_completed',dict(actor=actor,task_id=task_id,outcome=result['outcome'],model_requests=0))
        return resolved
    except BaseException:
        store._write("UPDATE planner_tasks SET state='ready',claimed_by=NULL,claimed_at=NULL WHERE id=? AND state='running' AND claimed_by=?",(task_id,worker))
        raise
