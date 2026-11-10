"""Upgrade a quiet checkpoint without a fresh run, verdict or spending allowance."""
import json
import uuid

from .execution_state import dump, stamp
from .incremental_review import inherit
from .review_store import fingerprint


def apply(store, run_id):
    with store._lock:
        store._db.execute('BEGIN IMMEDIATE')
        try:
            row=store._row('SELECT r.status,r.task_spec,e.phase,e.workflow FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?',(run_id,))
            if not row or row['status']!='paused' or row['phase']!='paused' or run_id in store._active_clocks:
                raise ValueError('策略升级要求静止的暂停检查点')
            task=json.loads(row['task_spec']);workflow=json.loads(row['workflow'])
            if task.get('incremental_checkpoint_upgrade'):
                store._db.execute('COMMIT')
                return task['incremental_checkpoint_upgrade']
            if store._row("SELECT 1 FROM poc_attempts WHERE run_id=? AND state='running'",(run_id,)) or store._row("SELECT 1 FROM planner_tasks WHERE run_id=? AND state='running'",(run_id,)):
                raise ValueError('仍有在途任务，不能升级检查点')
            old={i['item_id']:i for i in store._review_candidates(run_id,'final')}
            reviews=[dict(r) for r in store._rows("SELECT * FROM audit_review_items WHERE run_id=? AND phase='final'",(run_id,))
                     if old.get(r['item_id'],{}).get('revision')==r['revision']]
            allowances=[dict(r) for r in store._rows('SELECT * FROM audit_review_allowances WHERE run_id=?',(run_id,))
                        if old.get(r['item_id'],{}).get('revision')==r['revision']]
            task.update(review_reuse_policy='incremental-v1',risk_fact_policy='operation-v2',budget_exhaustion_policy='pause-v1')
            store._db.execute('UPDATE runs SET task_spec=? WHERE id=?',(dump(task),run_id))
            current={i['item_id']:i for i in store._review_candidates(run_id,'final')}
            batch_id=uuid.uuid4().hex;items=[];decisions=[]
            for review in reviews:
                item=current.get(review['item_id'])
                if not item:continue
                decision=json.loads(review['decision']);decision.update(revision=item['revision'],inherited_from_policy='checkpoint-upgrade')
                items.append(item);decisions.append(decision)
            if items:
                store._db.execute("INSERT INTO audit_review_batches(id,run_id,epoch,phase,input_hash,items,decisions,status,created_at,finished_at) VALUES(?,?,0,'final',?,?,?,'completed',?,?)",
                    (batch_id,run_id,fingerprint(items),dump(items),dump(decisions),stamp(),stamp()))
                for item,decision in zip(items,decisions):
                    store._db.execute('INSERT OR IGNORE INTO audit_review_items VALUES(?,?,?,?,?,?)',(run_id,'final',item['item_id'],item['revision'],batch_id,dump(decision)))
            for allowance in allowances:
                item=current.get(allowance['item_id'])
                if not item:continue
                allowance['revision']=item['revision']
                store._db.execute('INSERT OR IGNORE INTO audit_review_allowances ('+','.join(allowance)+') VALUES ('+','.join('?' for _ in allowance)+')',tuple(allowance.values()))
            info=task.get('continuation') or {};parent_id=info.get('parent_run_id');reused={}
            if parent_id:
                mapping={parent_id:run_id,**{old:new for new,old in (info.get('source_refs') or {}).items()}}
                for record in store.list_findings(run_id):
                    for verification in store.list_verifications(record['id']):
                        source=(verification.get('agent') or {}).get('continuation_source') or {}
                        if source.get('run_id')==parent_id:
                            mapping[source['verification_id']]=verification['id']
                reused=inherit(store,parent_id,run_id,mapping)
            # An old coordinator may already have skipped an exhausted stage.
            # Restore the earliest saved unfinished frontier, with its spent
            # limits intact, so the UI can add exactly the requested allowance.
            if store._row("SELECT 1 FROM planner_tasks WHERE run_id=? AND state IN ('ready','pending')",(run_id,)):
                workflow['stage']='discovery';workflow.pop('discovery_stop',None)
            elif store.pending_continuation_verifications(run_id):
                workflow['stage']='poc'
            result=dict(rebound_reviews=len(items),allowances_preserved=len(allowances),reused_from_parent=reused,
                        stage=workflow['stage'],at=stamp())
            task['incremental_checkpoint_upgrade']=result
            store._db.execute('UPDATE runs SET task_spec=? WHERE id=?',(dump(task),run_id))
            store._db.execute('UPDATE run_execution_state SET workflow=? WHERE run_id=?',(dump(workflow),run_id))
            store.append_event(run_id,None,'incremental_checkpoint_upgraded',result)
            store._db.execute('COMMIT')
        except BaseException:
            if store._db.in_transaction:store._db.execute('ROLLBACK')
            raise
    from .budget_checkpoints import pause
    pause(store,run_id,stage=result['stage'],message='未完成方向已恢复至原阶段；请在本记录补充或调拨阶段预算后继续。')
    return result
