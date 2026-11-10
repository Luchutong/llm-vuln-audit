"""Compile unresolved host identities into bounded reading tasks, never source verdicts."""
from __future__ import annotations

import hashlib
import json
import re
import uuid


def grant_paused_time(store, run_id, added_seconds, grant_id):
    """Apply an explicitly authorized, idempotent time grant at a quiet checkpoint.

    Request/tool caps, usage, attempts, findings and review allowances stay exact.
    An early time reservation may have advanced to POC with source tasks still
    ready: return only the recorded, unspent transfer to that original frontier.
    """
    from .execution_state import stamp
    from .workflow import poc_window_seconds

    if type(added_seconds) is not int or not 0 < added_seconds <= 7200 or not grant_id:
        raise ValueError('延时须为明确授权的 1..7200 秒及唯一授权 ID')
    with store._lock:
        store._db.execute('BEGIN IMMEDIATE')
        try:
            row = store._row('SELECT r.status,r.task_spec,e.phase,e.limits,e.workflow '
                             'FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?', (run_id,))
            if not row:
                raise ValueError('运行不存在')
            workflow = json.loads(row['workflow'] or '{}')
            previous = (workflow.get('time_grants') or {}).get(grant_id)
            if previous:
                if previous['added_seconds'] != added_seconds:
                    raise ValueError('同一授权 ID 不能改变额度')
                store._db.execute('COMMIT')
                return previous
            task = json.loads(row['task_spec'] or '{}')
            if (row['status'] != 'paused' or row['phase'] != 'paused' or run_id in store._active_clocks
                    or task.get('completion_recovery_policy') != 'assigned-gaps-v1'):
                raise ValueError('延时恢复要求已经静止的收尾暂停检查点')
            if (store._row("SELECT 1 FROM planner_tasks WHERE run_id=? AND state='running'", (run_id,))
                    or store._row("SELECT 1 FROM poc_attempts WHERE run_id=? AND state!='completed'", (run_id,))):
                raise ValueError('存在未关闭的源码或 POC 租约，不能延时恢复')
            limits = json.loads(row['limits'])
            before = dict(limits)
            limits['seconds'] += added_seconds
            moved = 0
            if (workflow['stage'] == 'poc'
                    and (workflow.get('discovery_stop') or {}).get('code') == 'poc_window_reserved'
                    and store._row("SELECT 1 FROM planner_tasks WHERE run_id=? AND state IN ('ready','pending')", (run_id,))):
                moved = min(int(workflow.get('transferred') or 0),
                            max(0, workflow['limits']['poc'] - workflow['used']['poc']))
                workflow['limits']['discovery'] += moved
                workflow['limits']['poc'] -= moved
                workflow['transferred'] = max(0, int(workflow.get('transferred') or 0) - moved)
                workflow['stage'] = 'discovery'
                workflow.pop('discovery_stop', None)
                workflow['poc_reserved_seconds'] = poc_window_seconds(limits['seconds'])
            grant = dict(added_seconds=added_seconds, before=before, after=limits,
                         returned_source_responses=moved, stage=workflow['stage'], at=stamp())
            workflow.setdefault('time_grants', {})[grant_id] = grant
            store._db.execute('UPDATE run_execution_state SET limits=?,workflow=?,updated_at=? WHERE run_id=?',
                              (json.dumps(limits), json.dumps(workflow), stamp(), run_id))
            store.append_event(run_id, None, 'completion_time_granted', dict(grant_id=grant_id, **grant))
            store._db.execute('COMMIT')
        except BaseException:
            if store._db.in_transaction:
                store._db.execute('ROLLBACK')
            raise
    return grant


def _bucket(path):
    for name in ('auth','account','ops','orders','wallet','content','catalog'):
        if '/public/' + name + '/' in path:
            return 'commerce' if name in {'orders','wallet'} else 'content' if name=='catalog' else name
    return 'auth' if path.endswith('/bootstrap.php') else 'ops' if '/app/src/' in path else 'infrastructure'


def seed_tasks(store, run_id, now, unresolved_risks):
    files = {f['path']:f for f in store.get_project_map(run_id)['files']
             if f.get('path') and int(f.get('line_count') or 0)>0 and not f.get('dependency_tree')}
    tasks = {t['task_key']:t for t in store.list_tasks(run_id,include_attempts=False)}
    records = store._audit_direction_records(run_id)
    open_leads = sorted((d for d in records.values() if d['state'] in {'pending','assigned'}),key=lambda d:d['id'])
    bootstrap = next((p for p in files if p.endswith('/app/src/bootstrap.php')),None)
    groups=[]

    def append(paths, *, lead=None, obligation=None, owner=None):
        paths=set(paths)&files.keys()
        if bootstrap and any(p.endswith('.php') for p in paths):paths.add(bootstrap)
        if not paths:
            raise ValueError('收尾项没有冻结源码路径，须保留具体缺口，不能无依据排除')
        if len(paths)>16:raise ValueError('单项收尾超过16个源码路径，须先缩小具体取证范围')
        bucket=_bucket(sorted(paths-{bootstrap})[0]) if paths-{bootstrap} else 'auth'
        group=next((g for g in groups if g['bucket']==bucket and (not owner or g['owner'] in {None,owner})
                    and len(g['paths']|paths)<=16 and len(g['directions'])<12),None)
        if group is None:
            group=dict(bucket=bucket,paths=set(),directions=[],obligations=[],owner=owner);groups.append(group)
        group['paths']|=paths
        if owner:group['owner']=owner
        if lead:group['directions'].append(lead['id'])
        if obligation:group['obligations'].append(obligation['id'])

    # Pending candidates stay on their original owner and gain their actual anchor.
    for task in tasks.values():
        pending=[c for c in (task.get('result') or {}).get('candidate_journal') or [] if c.get('status')=='pending']
        if pending:
            append([c['primary_location']['path'] for c in pending],owner=task['task_key'])
    for lead in open_leads:
        paths={p for p in lead.get('paths') or [] if p in files}
        if not paths:
            text=lead['text']
            paths.update(p for p in files if p in text or any(p.endswith('/'+n) for n in
                re.findall(r'[A-Za-z0-9_./-]+\.(?:php|py|ini|sh)',text)))
        if not paths:
            modules=[m for m in ('orders','wallet','content','auth','account','ops') if m in lead['text']]
            paths.update(p for p in files if any('/public/'+m+'/' in p for m in modules))
        if not paths:
            prior=tasks.get(lead['origin_task_key'],{})
            paths.update(r['path'] for r in (prior.get('context_spec') or {}).get('source_refs') or [] if r.get('path') in files)
        append(paths,lead=lead)
    for risk in (store.risk_coverage(run_id) or {}).get('items') or []:
        if risk['id'] in unresolved_risks:
            append([risk['path']],obligation=risk)
    # Reuse the same identities for inherited work; newly seeded tasks carry no verdict.
    session=store.get_planner_session(run_id);goal=store.get_task_goal(run_id)
    manifest=[];proposals=[]
    for index,g in enumerate(groups):
        key=g['owner'] or 'close-'+hashlib.sha256(json.dumps([g['directions'],g['obligations'],sorted(g['paths'])]).encode()).hexdigest()[:16]
        existing=tasks.get(key)
        refs=[dict(path=p,start_line=1,end_line=min(400,int(files[p]['line_count'])),reason='宿主分派的未决项原始源码') for p in sorted(g['paths'])]
        spec=dict(objective_ref='objective-main',direction_ids=g['directions'],obligation_ids=g['obligations'],
            source_refs=refs,scope_paths=[],target_symbols=[],query_hints=[],closure_inspection=True)
        title='逐项收尾：'+g['bucket']
        objective='逐条调查宿主分派的 direction_ids、风险义务和本任务 pending 候选。读取已提供的完整原始源码，逐项提交 direction_results；同根因用 finding_references。'
        criteria='每个已分派 ID 恰好给 supported/no_evidence/needs_evidence 及实际源码依据；排除须有 disproof，支持须引用实际有效 finding。保留所有未决候选；核对缺失名称在冻结源码的边界，不能猜测外部实现。'
        if existing:
            # Preserve dependencies, history and the candidate journal; only its next read scope changes.
            spec['closure_previous_objective']=existing['objective']
            store._db.execute("UPDATE planner_tasks SET title=?,objective=?,acceptance_criteria=?,context_spec=?,state='ready',error=NULL,finished_at=NULL,max_attempts=attempts+1,updated_at=? WHERE id=?",
                (title,objective,criteria,json.dumps(spec,ensure_ascii=False),now,existing['id']))
        else:
            ident=uuid.uuid4().hex
            store._db.execute('INSERT INTO planner_tasks (id,run_id,goal_id,plan_id,task_key,title,objective,acceptance_criteria,rationale_summary,context_spec,dependencies,session_id,priority,state,max_attempts,attempts,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)',
                (ident,run_id,goal['id'],None,key,title,objective,criteria,'按冻结未决清单逐项取证，未自动结算。',json.dumps(spec,ensure_ascii=False),'[]',session['session_id']+':'+ident[:10],100-index,'ready',1,now,now))
        proposals.append(dict(task_key=key,direction_ids=g['directions']))
        manifest.append(dict(task_key=key,source_paths=sorted(g['paths']),direction_ids=g['directions'],obligation_ids=g['obligations'],candidate_owner=bool(existing)))
    store._apply_direction_updates_tx(run_id,[],proposals,[])
    # Any inherited open task without a candidate is still explicit work, never cancelled here.
    store.append_event(run_id,None,'completion_frontier_seeded',dict(tasks=manifest,unresolved_directions=len(open_leads)))
    return manifest
