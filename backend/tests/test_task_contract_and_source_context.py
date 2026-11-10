"""Bound actual frozen source and task identities before another model attempt."""
import copy
import asyncio
import json
import pytest

from jsonschema import Draft202012Validator

from audit.schemas import PlannerDecision
from audit.task_contract import named_source_paths,planner_schema
from tests.test_goal_tasks import store,repository,make_zip  # noqa: F401
from tests.test_host_queue import hosted  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_goal_tasks import proposal
from tests.test_incremental_budget_checkpoints import enable
from audit.budget_checkpoints import pause
from audit.task_contract import repair_paused_source_task
from audit import worker as worker_module
from tests.test_goal_tasks import make_worker


def test_named_pending_work_loads_real_files_instead_of_only_the_bootstrap(repository):
    snap=repository.import_zip(make_zip({'src/bootstrap.php':'<?php\nfunction boot() {}\n',
        'public/auth/login.php':'<?php\nboot();\n', 'public/health.php':'<?php echo "ok";\n',
        'public/index.php':'<?php echo "index";\n'}),'context.zip')
    task=dict(objective='补查实际尚未读取的入口',context_spec=dict(source_refs=[dict(path='src/bootstrap.php',start_line=1,end_line=2)]),
        result=dict(remaining_work=['补读 public/health.php 与 public/index.php 原始入口'],
                    candidate_journal=[dict(status='pending',primary_location=dict(path='src/bootstrap.php',line=1),
                        next_step='补读 public/auth/login.php 核对真实会话链；并寻找 absent/lib.php')]))
    before=copy.deepcopy(task)
    old=repository.build_context_bundle(snap['id'],task,workflow_policy='discovery_first')
    assert {e['path'] for e in old['excerpts']}=={'src/bootstrap.php'}
    bundle=repository.build_context_bundle(snap['id'],task,workflow_policy='discovery_first',preload_named_sources=True)
    assert {e['path'] for e in bundle['excerpts']}=={'src/bootstrap.php','public/auth/login.php','public/health.php','public/index.php'}
    assert any('absent/lib.php'==u.get('path') for u in bundle['unresolved_dependencies'])
    assert not any(e['path']=='absent/lib.php' for e in bundle['excerpts'])
    assert task==before


def test_ambiguous_names_and_broad_directories_do_not_expand_source(repository):
    snap=repository.import_zip(make_zip({'a/index.php':'<?php\n', 'b/index.php':'<?php\n', 'boot.php':'<?php\n'}),'ambiguous.zip')
    task=dict(objective='检查 index.php 与 broad directory',context_spec=dict(source_refs=[dict(path='boot.php',start_line=1,end_line=1)],scope_paths=['a','b']))
    result=repository.build_context_bundle(snap['id'],task,workflow_policy='discovery_first',preload_named_sources=True)
    assert {e['path'] for e in result['excerpts']}=={'boot.php'}
    assert any(u.get('reason')=='named source is ambiguous' for u in result['unresolved_dependencies'])
    paths,missing=named_source_paths(dict(objective='读 a/index.php'),{'a/index.php','b/index.php'})
    assert paths==['a/index.php'] and not missing


def test_named_context_keeps_the_existing_file_and_byte_bounds(repository):
    files={f'src/f{i}.php':'<?php\n'+('x'*250+'\n')*5 for i in range(20)}
    snap=repository.import_zip(make_zip(files),'bounded.zip')
    task=dict(objective='read '+','.join(sorted(files)),source_refs=[])
    bundle=repository.build_context_bundle(snap['id'],task,max_bytes=1024,workflow_policy='discovery_first',preload_named_sources=True)
    assert len(bundle['excerpts'])<=16
    assert sum(len(f"{e['path']}:{line['number']} | {line['text']}\n".encode()) for e in bundle['excerpts'] for line in e['lines'])<=1024
    assert bundle['unresolved_dependencies'] or bundle['relation_summary']['omitted_excerpts']


def test_planner_menu_rejects_fake_directories_and_completed_task_redefinition():
    project=dict(scope=['app/login.php','app/bootstrap.php'],files=[dict(path=p,line_count=10,kind='text') for p in ['app/login.php','app/bootstrap.php']],symbols=[])
    tasks=[dict(task_key='auth-session-boundary',state='completed'),dict(task_key='pending-owner',state='blocked')]
    schema=planner_schema(PlannerDecision.model_json_schema(),project,tasks)
    Draft202012Validator.check_schema(schema)
    check=Draft202012Validator(schema)
    value=dict(basis_summary='按真实入口读取尚未结算的方向。',tasks=[dict(task_key='new-gap',title='读取真实入口',
        objective='补充读取真实入口与权限边界',acceptance_criteria='引用实际源码行结算当前方向',rationale_summary='当前仍需补证',
        source_refs=[dict(path='app/login.php',start_line=1,end_line=3)])])
    check.validate(value)
    changed=copy.deepcopy(value);changed['tasks'][0]['source_refs'][0]['path']='app/lib/unknown.php'
    assert not check.is_valid(changed)
    changed=copy.deepcopy(value);changed['tasks'][0]['scope_paths']=['app/lib']
    assert not check.is_valid(changed)
    changed=copy.deepcopy(value);changed['tasks'][0]['task_key']='auth-session-boundary'
    assert not check.is_valid(changed)
    changed=copy.deepcopy(value);changed['tasks'][0]['task_key']='pending-owner'
    assert check.is_valid(changed)
    changed=copy.deepcopy(value);changed['tasks'][0].update(source_refs=[],scope_paths=['app'])
    assert not check.is_valid(changed)


def blocked_source_task(hosted):
    store,repo,run=hosted
    enable(store,run)
    project=store.get_project_map(run['id']);paths=project['scope']
    owner=proposal('source-owner',path=paths[0],start=1,end=1)
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='继续具体源码取证',tasks=[owner])
    task=store.list_tasks(run['id'],include_attempts=False)[0]
    result=dict(candidate_journal=[dict(candidate_id='pending',status='pending',blocked_on='source',
                                       hypothesis='入口与共享模块的认证边界尚待补读',
                                       primary_location=dict(path=paths[0],line=1),next_step='读取 '+paths[1])])
    store._write("UPDATE planner_tasks SET state='blocked',attempts=2,max_attempts=3,result=?,error='missing source' WHERE id=?",
                 (json.dumps(result),task['id']))
    pause(store,run['id'],stage='discovery',reason='source_evidence_required');store.quiesce_execution(run['id'])
    return store,repo,run,task,paths[1]


def test_paused_context_repair_reuses_one_remaining_attempt_without_resetting_history(hosted):
    store,repo,run,task,needed=blocked_source_task(hosted)
    before=store.get_planner_task(task['id']);usage=store.execution_summary(run['id'])
    raw_result=store._row('SELECT result FROM planner_tasks WHERE id=?',(task['id'],))[0]
    store._write("INSERT INTO audit_review_allowances VALUES(?,'final','item','version',2,?, 'contract:focus',2,'same_error')",
                 (run['id'],json.dumps({'contract:focus':2})))
    allowances=store.review_allowances(run['id'],'final')
    repair=repair_paused_source_task(store,run['id'],task['id'])
    after=store.get_planner_task(task['id'])
    assert needed in repair['added_paths'] and after['state']=='ready'
    assert after['attempts']==2 and after['max_attempts']==3
    assert after['result']['candidate_journal']==before['result']['candidate_journal']
    assert store._row('SELECT result FROM planner_tasks WHERE id=?',(task['id'],))[0]==raw_result
    current=store.execution_summary(run['id'])
    assert current['run_limits']==usage['run_limits'] and current['run_usage']==usage['run_usage']
    assert store.review_allowances(run['id'],'final')==allowances
    assert repair_paused_source_task(store,run['id'],task['id'])==repair
    assert len(store._rows("SELECT 1 FROM events WHERE run_id=? AND kind='source_context_repaired'",(run['id'],)))==1
    store._write("UPDATE planner_tasks SET state='blocked' WHERE id=?",(task['id'],))
    repair_paused_source_task(store,run['id'],task['id'])
    assert store.get_planner_task(task['id'])['state']=='blocked'


@pytest.mark.parametrize('change',["UPDATE runs SET status='running' WHERE id=?",
                                  "UPDATE planner_tasks SET attempts=max_attempts WHERE run_id=?",
                                  "UPDATE planner_tasks SET state='completed' WHERE run_id=?"])
def test_context_repair_refuses_active_or_spent_or_completed_work(hosted,change):
    store,repo,run,task,needed=blocked_source_task(hosted)
    store._write(change,(run['id'],))
    with pytest.raises(ValueError):repair_paused_source_task(store,run['id'],task['id'])
    assert 'source_context_repair' not in store.get_planner_task(task['id'])['context_spec']


@pytest.mark.parametrize('poc_state',['claimed','running','interrupted','completed'])
def test_context_repair_distinguishes_active_poc_leases_from_terminal_history(hosted,poc_state):
    store,repo,run,task,needed=blocked_source_task(hosted)
    store._write('INSERT INTO poc_attempts(key,run_id,revision,target_key,state,created_at,updated_at) VALUES(?,?,1,?,?,?,?)',
                 ('lease',run['id'],'target',poc_state,'2026-01-01','2026-01-01'))
    if poc_state in {'claimed','running'}:
        with pytest.raises(ValueError,match='租约'):repair_paused_source_task(store,run['id'],task['id'])
    else:
        assert needed in repair_paused_source_task(store,run['id'],task['id'])['added_paths']
    assert store._row('SELECT state FROM poc_attempts WHERE key=?',('lease',))[0]==poc_state


def test_source_blocker_pauses_before_stage_transfer_or_poc(hosted,monkeypatch):
    store,repo,run,task,needed=blocked_source_task(hosted)
    assert store.resume_run(run['id'])
    run=store.claim_next_run()
    limits=store.workflow_state(run['id'])['limits']
    async def plan(**kwargs):
        return dict(decision=dict(goal_state='continue',basis_summary='仍缺少候选所需源码，保留具体缺口。',
                                 tasks=[],updates=[],missing_context=[needed]),usage={},terminal_reason='completed')
    async def forbidden(*args,**kwargs):pytest.fail('source blocker must pause before POC or final review')
    monkeypatch.setattr(worker_module,'plan_audit_frontier',plan)
    monkeypatch.setattr(worker_module.PocVerifier,'verify_standing',forbidden)
    asyncio.run(make_worker(store,repo)._execute(run))
    summary=store.execution_summary(run['id'])
    assert store.get_run(run['id'])['status']=='paused'
    assert summary['workflow']['stage']=='discovery' and summary['workflow']['limits']==limits
    assert summary['stop_reason']['code']=='source_evidence_required'
    assert not store._row('SELECT 1 FROM events WHERE run_id=? AND kind=?',(run['id'],'workflow_stage_changed'))


def test_a_source_gap_does_not_relabel_an_exhausted_stage_as_free_to_resume(hosted,monkeypatch):
    store,repo,run,task,needed=blocked_source_task(hosted)
    assert store.resume_run(run['id'])
    run=store.claim_next_run()
    workflow=store.workflow_state(run['id']);workflow['limits']['discovery']=workflow['used']['discovery']
    store._write('UPDATE run_execution_state SET workflow=? WHERE run_id=?',(json.dumps(workflow),run['id']))
    async def forbidden(**kwargs):pytest.fail('exhausted discovery must pause before planning')
    monkeypatch.setattr(worker_module,'plan_audit_frontier',forbidden)
    asyncio.run(make_worker(store,repo)._execute(run))
    summary=store.execution_summary(run['id'])
    assert summary['stop_reason']['code']=='stage_budget_exhausted'
    assert summary['workflow']['stage']=='discovery'
    assert not store.resume_run(run['id'])
