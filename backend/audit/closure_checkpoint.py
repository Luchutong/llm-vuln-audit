"""Repair direction ownership at a quiet checkpoint, without supplying verdicts."""
import hashlib
import json
import uuid


def repair(store, run_id, assignments):
    """Bind an explicit, complete remaining-work manifest to bounded source tasks.

    A human supplies the reading scope. Existing source judgments, task attempts,
    candidate history, review allowances, model usage and caps stay untouched.
    """
    from .execution_state import stamp
    encoded=json.dumps(assignments,sort_keys=True,ensure_ascii=False)
    identity=hashlib.sha256(encoded.encode()).hexdigest()
    with store._lock:
        store._db.execute('BEGIN IMMEDIATE')
        try:
            row=store._row('SELECT r.status,r.task_spec,e.phase,e.workflow FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?',(run_id,))
            if not row:raise ValueError('运行不存在')
            workflow=json.loads(row['workflow'] or '{}');spec=json.loads(row['task_spec'] or '{}')
            previous=(workflow.get('closure_checkpoint_repairs') or {}).get(identity)
            if previous:
                store._db.execute('COMMIT');return previous
            if (row['status']!='paused' or row['phase']!='paused' or run_id in store._active_clocks
                    or spec.get('completion_recovery_policy')!='assigned-gaps-v1'):
                raise ValueError('仅可修复静止的逐项收尾暂停记录')
            if store.task_queue_state(run_id)['active'] or store.worker_candidate_gaps(run_id):
                raise ValueError('仍有执行前沿或未决候选，不能替换原工作归属')
            if store._row("SELECT 1 FROM poc_attempts WHERE run_id=? AND state IN ('claimed','running')",(run_id,)):
                raise ValueError('仍有 POC 租约')
            if not (store.coverage_review(run_id) or {}).get('complete'):
                raise ValueError('尚有未覆盖源码，不适用收尾账本修复')
            records=store._audit_direction_records(run_id)
            tasks={t['task_key']:t for t in store.list_tasks(run_id)}
            findings=store.list_findings(run_id)
            unready={d['id'] for d in records.values() if d['state'] in {'pending','assigned'}
                     and not store.direction_resolution_context(run_id,d,tasks=tasks,findings=findings)['can_resolve']}
            selected=[d for a in assignments for d in a['direction_ids']]
            if len(selected)!=len(set(selected)) or set(selected)!=unready:
                raise ValueError('清单必须恰好覆盖全部缺取证结果的开放方向，不能重复或遗漏')
            project=store.get_project_map(run_id)
            files={f['path']:f for f in project['files'] if f['path'] in project['scope'] and int(f.get('line_count') or 0)>0}
            goal=store.get_task_goal(run_id);session=store.get_planner_session(run_id)
            if goal['status']!='open' or len(assignments)>goal['max_total_attempts']-goal['attempts']:
                raise ValueError('现有共享尝试额度不足，不能增加额度')
            result=[];proposals=[];at=stamp()
            for index,a in enumerate(assignments):
                paths=sorted(set(a['source_paths']));ids=sorted(a['direction_ids'])
                if not 1<=len(paths)<=16 or not set(paths)<=files.keys() or not 1<=len(ids)<=12:
                    raise ValueError('每项需1..16个真实源码文件及1..12个方向 ID')
                ident=uuid.uuid4().hex;key='settle-'+hashlib.sha256((identity+str(index)).encode()).hexdigest()[:16]
                refs=[dict(path=p,start_line=1,end_line=min(400,int(files[p]['line_count'])),reason='当前未闭环方向的明确补证范围') for p in paths]
                context=dict(objective_ref='objective-main',direction_ids=ids,obligation_ids=[],source_refs=refs,
                             scope_paths=[],target_symbols=[],query_hints=[],closure_inspection=True)
                objective=('仅结算本项明确分派的 direction_ids。逐条对齐已读源码与当前 finding，'
                           '相同根因使用 finding_references；不同问题仍保留。'+a['objective'])
                criteria=('对每个已分派 ID 恰好给出 supported/no_evidence/needs_evidence。'
                          'supported 同次引用对应有效 finding；no_evidence 给有原始行号的 disproof。'
                          '不存在的文件只说明冻结范围边界，不虚构外部实现；无需泛化挖掘。')
                store._db.execute('INSERT INTO planner_tasks (id,run_id,goal_id,plan_id,task_key,title,objective,acceptance_criteria,rationale_summary,context_spec,dependencies,session_id,priority,state,max_attempts,attempts,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)',
                    (ident,run_id,goal['id'],None,key,a['title'],objective,criteria,'修复收尾方向与取证任务的归属；不自动给漏洞或安全结论。',
                     json.dumps(context,ensure_ascii=False),'[]',session['session_id']+':'+ident[:10],100-index,'ready',1,at,at))
                proposals.append(dict(task_key=key,direction_ids=ids))
                result.append(dict(task_key=key,direction_ids=ids,source_paths=paths))
            store._apply_direction_updates_tx(run_id,[],proposals,[])
            repaired=dict(identity=identity,tasks=result,at=at,added_budget=dict(responses=0,tools=0,seconds=0))
            workflow.setdefault('closure_checkpoint_repairs',{})[identity]=repaired
            store._db.execute('UPDATE run_execution_state SET workflow=? WHERE run_id=?',(json.dumps(workflow),run_id))
            store.append_event(run_id,None,'closure_checkpoint_repaired',repaired)
            store._db.execute('COMMIT');return repaired
        except BaseException:
            if store._db.in_transaction:store._db.execute('ROLLBACK')
            raise
