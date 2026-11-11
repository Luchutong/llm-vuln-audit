"""Freeze navigation choices and preload explicitly named source, never verdicts."""
from pathlib import PurePosixPath
import json
import re

SOURCE_NAME = re.compile(r'[A-Za-z0-9_./-]+\.(?:php[3-8]?|phtml|inc|py|js|ts|tsx|jsx|sh|ya?ml|json|ini|conf)\b')


def named_source_paths(task, files):
    """Only unambiguous names in the task's own remit or saved pending work."""
    result=task.get('result') or {}
    texts=[task.get('objective'),task.get('acceptance_criteria'),
           *(result.get('remaining_work') or []),*(result.get('missing_context') or [])]
    for candidate in result.get('candidate_journal') or []:
        if candidate.get('status')=='pending':
            texts.extend([candidate.get('hypothesis'),candidate.get('next_step'),
                          *(candidate.get('missing_context') or []),
                          (candidate.get('primary_location') or {}).get('path')])
    names=sorted({name for text in texts if isinstance(text,str) for name in SOURCE_NAME.findall(text)})
    chosen=set();unresolved=[]
    for name in names:
        matches=[name] if name in files else sorted(p for p in files if p.endswith('/'+name))
        if len(matches)==1:
            chosen.add(matches[0])
        else:
            unresolved.append(dict(path=name,reason='named source is ambiguous' if matches else 'named source is absent from frozen scope'))
    return sorted(chosen),unresolved


def repair_paused_source_task(store, run_id, task_id):
    """Deliver missing, explicitly requested frozen source using an existing attempt.

    This changes navigation only. Candidate journals, findings, read ledgers,
    review allowances, attempt counts and run budgets remain untouched.
    """
    from .execution_state import stamp

    with store._lock:
        store._db.execute('BEGIN IMMEDIATE')
        try:
            row=store._row('SELECT r.status,e.phase FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?',(run_id,))
            task=store.get_planner_task(task_id)
            if not row or not task or task['run_id']!=run_id:
                raise ValueError('运行或任务不存在')
            context=dict(task.get('context_spec') or {})
            previous=context.get('source_context_repair')
            if previous:
                store._db.execute('COMMIT')
                return previous
            if row['status']!='paused' or row['phase']!='paused' or run_id in store._active_clocks:
                raise ValueError('源码上下文修复要求静止的暂停检查点')
            if (store._row("SELECT 1 FROM planner_tasks WHERE run_id=? AND state='running'",(run_id,))
                    or store._row("SELECT 1 FROM poc_attempts WHERE run_id=? AND state IN ('claimed','running')",(run_id,))):
                raise ValueError('仍有执行中的源码或 POC 租约')
            pending=[c for c in (task.get('result') or {}).get('candidate_journal') or []
                     if c.get('status')=='pending' and c.get('blocked_on')=='source']
            if task['state']!='blocked' or not pending or task['attempts']>=task['max_attempts']:
                raise ValueError('仅可恢复有剩余尝试且明确缺源码的阻塞任务')
            project=store.get_project_map(run_id)
            files={f['path']:f for f in project['files'] if f.get('path') in project['scope']
                   and f.get('kind')!='binary' and int(f.get('line_count') or 0)>0}
            paths,missing=named_source_paths(task,files)
            refs=list(context.get('source_refs') or [])
            existing={r['path'] for r in refs}
            added=[p for p in paths if p not in existing]
            if not added or len(existing|set(added))>16:
                raise ValueError('没有可新增的明确源码，或超过16个文件的上下文上限')
            refs.extend(dict(path=p,start_line=1,end_line=min(400,int(files[p]['line_count'])),
                             reason='补齐该任务已明确请求但未交付的冻结源码') for p in added)
            repair=dict(policy='named-source-v1',task_id=task_id,added_paths=added,unresolved=missing,
                        attempts=task['attempts'],max_attempts=task['max_attempts'],at=stamp())
            context.update(source_refs=refs,source_context_repair=repair)
            store._db.execute("UPDATE planner_tasks SET context_spec=?,state='ready',error=NULL,finished_at=NULL,updated_at=? WHERE id=?",
                              (json.dumps(context,ensure_ascii=False),repair['at'],task_id))
            store.append_event(run_id,None,'source_context_repaired',repair)
            store._db.execute('COMMIT')
            return repair
        except BaseException:
            if store._db.in_transaction:
                store._db.execute('ROLLBACK')
            raise


def planner_schema(schema, project_map, tasks, *, closure_direction_ids=None):
    """Small maps advertise exact legal files, directories and redefinable keys."""
    files=sorted({f['path'] for f in project_map.get('files') or [] if f.get('path') and f.get('kind')!='binary'
                  and int(f.get('line_count') or 0)>0})
    if project_map.get('scope'):
        files=[p for p in files if p in project_map['scope']]
    directories=sorted({str(parent) for path in files for parent in PurePosixPath(path).parents if str(parent)!='.'})
    defs=schema['$defs'];proposal=defs['PlannerTaskProposal'];props=proposal['properties']
    if closure_direction_ids is not None:
        proposal['required']=list(dict.fromkeys([*(proposal.get('required') or []),'direction_ids']))
        props['direction_ids'].update(minItems=1)
        if closure_direction_ids:
            props['direction_ids']['items']={'type':'string','enum':sorted(set(closure_direction_ids))}
        else:
            schema['properties']['tasks']['maxItems']=0
    if files and len(files)<=256:
        defs['PlannerSourceRef']['properties']['path'].update(enum=files)
        if len(files)+len(directories)<=1024:
            props['scope_paths']['items']={'type':'string','enum':sorted(files+directories)}
        proposal['anyOf']=[
            dict(required=['source_refs'],properties=dict(source_refs=dict(type='array',minItems=1))),
            dict(required=['scope_paths'],properties=dict(scope_paths=dict(type='array',minItems=1,items=dict(type='string',enum=files)))),
            dict(required=['target_symbols'],properties=dict(target_symbols=dict(type='array',minItems=1)))]
        names=sorted({str(s.get(key)) for s in project_map.get('symbols') or [] for key in ('name','short_name')
                      if s.get('path') in files and s.get(key)})
        if names and len(names)<=256:
            props['target_symbols']['items']={'type':'string','enum':names}
        elif not names:
            props['target_symbols']['maxItems']=0
    locked=sorted(t['task_key'] for t in tasks if t.get('task_key') and t.get('state') not in {'pending','ready','deferred','blocked'})
    if locked:
        props['task_key']['not']={'enum':locked}
    keys=sorted({t['task_key'] for t in tasks if t.get('task_key')})
    if keys:
        defs['PlannerTaskUpdate']['properties']['task_key'].update(enum=keys)
    else:
        schema['properties']['updates']['maxItems']=0
    return schema
