"""Durable budget checkpoints and explicit, idempotent grants on the same run."""
import json

from .execution_state import dump, stamp


def enabled(run):
    spec = (run or {}).get('task_spec') or {}
    return spec.get('orchestration_policy') == 'host-queue-v1' and spec.get('budget_exhaustion_policy') == 'pause-v1'


def reuse_source_balance_tx(store, run_id, workflow):
    """Explicit resume of an evidence gap, inside resume_run's transaction."""
    if (workflow.get('budget_pause') or {}).get('code') != 'source_evidence_required':
        return False
    row=store._row('SELECT limits,responses_used,tools_used,active_elapsed_ms FROM run_execution_state WHERE run_id=?',(run_id,))
    limits=json.loads(row['limits'] or '{}')
    remaining=limits.get('responses',0)-row['responses_used']
    if (remaining<=0 or limits.get('seconds',0)<=row['active_elapsed_ms']/1000
            or (limits.get('tools',0)>0 and limits['tools']<=row['tools_used'])
            or sum(workflow['used'].values())!=row['responses_used']):
        return False
    previous=dict(workflow['limits'])
    workflow['limits']=dict(workflow['used'])
    workflow['limits']['discovery']+=remaining
    workflow.update(stage='discovery',source='derived',transferred=0)
    workflow.pop('budget_pause',None);workflow.pop('discovery_stop',None)
    store._db.execute('UPDATE run_execution_state SET workflow=?,stop_reason=NULL,updated_at=? WHERE run_id=?',
                      (dump(workflow),stamp(),run_id))
    store.append_event(run_id,None,'run_balance_reused',dict(responses_remaining=remaining,
        added_budget=dict(responses=0,tools=0,seconds=0),before=previous,after=workflow['limits']))
    return True


def pause(store, run_id, *, stage=None, reason='stage_budget_exhausted', message=None, epoch=None):
    with store._lock:
        row = store._row('SELECT r.status,e.claim_epoch,e.workflow FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?', (run_id,))
        if not row or row['status'] not in {'running', 'paused'} or (epoch is not None and row['claim_epoch'] != epoch):
            return False
        workflow = json.loads(row['workflow'] or '{}')
        if workflow.get('budget_pause'):
            return True
        stage = stage or workflow.get('stage')
        checkpoint = dict(code=reason, stage=stage, resumable=True,
            message=message or f'{stage} 阶段预算不足，已暂停；可在本记录追加预算后继续。', at=stamp())
        workflow['budget_pause'] = checkpoint
        store._db.execute("UPDATE runs SET status='paused' WHERE id=?", (run_id,))
        store._db.execute('UPDATE run_execution_state SET workflow=?,stop_reason=?,updated_at=? WHERE run_id=?',
                          (dump(workflow), dump(checkpoint), stamp(), run_id))
        store.append_event(run_id, None, 'run_budget_paused', checkpoint)
        return True


def grant(store, run_id, payload):
    from .schemas import RunLimits
    with store._lock:
        store._db.execute('BEGIN IMMEDIATE')
        try:
            prior = store._row("SELECT payload FROM events WHERE run_id=? AND kind='run_budget_granted' AND json_extract(payload,'$.request.request_id')=?", (run_id, payload['request_id']))
            if prior:
                result = json.loads(prior[0])
                if result['request'] != payload:
                    raise ValueError('相同 request_id 不能改变追加预算')
                store._db.execute('COMMIT')
                return result
            row = store._row('SELECT r.status,e.phase,e.limits,e.workflow,e.responses_used,e.tools_used,e.active_elapsed_ms FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?', (run_id,))
            if not row or row['status'] != 'paused' or row['phase'] != 'paused' or run_id in store._active_clocks:
                raise ValueError('追加预算要求已静止的暂停检查点')
            if store._row("SELECT 1 FROM runs WHERE status IN ('pending','running','paused') AND json_extract(task_spec,'$.continuation.parent_run_id')=?", (run_id,)):
                raise ValueError('关联任务尚未结束，不能同时恢复父任务')
            if store._row("SELECT 1 FROM planner_tasks WHERE run_id=? AND state='running'", (run_id,)) or store._row("SELECT 1 FROM poc_attempts WHERE run_id=? AND state='running'", (run_id,)):
                raise ValueError('仍有在途源码或 POC，等待其关闭后追加预算')
            goal = store.get_task_goal(run_id)
            if goal and goal['status'] != 'open':
                raise ValueError('任务目标已结算，不能修改终态预算')
            before = json.loads(row['limits'] or '{}')
            after = RunLimits(**{key: before[key] + payload[key] for key in ('responses','tools','seconds')}).model_dump()
            workflow = json.loads(row['workflow'] or '{}')
            automatic = payload.get('stage','auto') == 'auto'
            stage = payload.get('stage','auto')
            if not workflow:
                raise ValueError('本运行没有可接续的阶段账本')
            if automatic:
                task = json.loads(store._row('SELECT task_spec FROM runs WHERE id=?',(run_id,))[0] or '{}')
                review_only = (task.get('continuation') or {}).get('mode') == 'review'
                source_work = store._row("SELECT 1 FROM planner_tasks WHERE run_id=? AND state IN ('ready','pending','blocked') LIMIT 1",(run_id,))
                stage = ('review' if review_only else 'discovery' if source_work else
                         (workflow.get('budget_pause') or {}).get('stage') or workflow['stage'])
                if sum(workflow['used'].values()) != row['responses_used']:
                    raise ValueError('阶段消耗与整次账本不一致，需先核对检查点')
                # Resume work in order using the shared unspent balance. Normal
                # host reservation protects review; no spent allowance is reset.
                workflow['limits'] = dict(workflow['used'])
                workflow['limits'][stage] += after['responses'] - row['responses_used']
            moved = payload.get('transfer_responses', 0)
            if moved:
                source = payload['transfer_from']
                if moved > workflow['limits'][source] - workflow['used'][source]:
                    raise ValueError('不能调拨已经消耗的阶段请求')
                workflow['limits'][source] -= moved
            if not automatic:
                workflow['limits'][stage] += payload['responses'] + moved
            if sum(workflow['limits'].values()) != after['responses']:
                raise ValueError('阶段预算总和与整次上限不一致')
            if payload.get('resume', True):
                if after['responses'] <= row['responses_used'] or after['seconds'] <= row['active_elapsed_ms']/1000 or (after['tools'] and after['tools'] <= row['tools_used']):
                    raise ValueError('整次预算仍不足；请补齐耗尽的预算维度')
                if workflow['limits'][stage] <= workflow['used'][stage]:
                    raise ValueError('当前阶段请求仍已耗尽；请增加请求或明确调拨未使用额度')
            workflow['stage'] = stage
            # Explicit grants reserve the selected allocation: automatic review
            # estimates may request more budget but cannot take this grant away.
            workflow['source'] = 'derived' if automatic else 'explicit'
            workflow.pop('budget_pause', None)
            if stage == 'discovery':
                workflow.pop('discovery_stop', None)
            result = dict(request=payload, before=before, after=after, stage=stage, at=stamp())
            store._db.execute('UPDATE run_execution_state SET limits=?,workflow=?,stop_reason=NULL,updated_at=? WHERE run_id=?',
                              (dump(after), dump(workflow), stamp(), run_id))
            store.append_event(run_id, None, 'run_budget_granted', result)
            store._db.execute('COMMIT')
            return result
        except BaseException:
            if store._db.in_transaction:
                store._db.execute('ROLLBACK')
            raise
