"""Small offline closure checks: temporary SQLite, no models or runner."""
import copy
import hashlib
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient
from types import SimpleNamespace

from audit.db import Store
from audit.source import SourceRepository
from audit.review_store import validate_batch
from audit.frozen_reports import materialize
from audit.runtimes.claude_poc import StorePocRequestGateway
from tests.test_goal_tasks import TASK, create_planner_run, proposal, _conclusion_finding


@pytest.fixture
def state(tmp_path):
    store = Store(tmp_path / 'audit.db')
    repo = SourceRepository(tmp_path / 'sources')
    store._report_repository = repo
    run, project_map = create_planner_run(store, repo, task={
        **TASK, 'max_planner_rounds': 24, 'workflow_policy': 'discovery_first', 'review_policy': 'batch-v1',
    })
    store._write('UPDATE run_execution_state SET limits=?,workflow=? WHERE run_id=?', (json.dumps({'responses':256,'tools':2048,'seconds':1800}), json.dumps({'version':'discovery-first-v1','stage':'discovery','limits':{'discovery':180,'poc':64,'review':12},'used':{'discovery':0,'poc':0,'review':0},'review_reserved_seconds':60,'review_reserved_rounds':4}),run['id']))
    try:
        yield store, repo, run
    finally:
        store.close()


def commit(store, run, batch, choice='retain'):
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    decisions = [dict(item_id=i['item_id'], revision=i['revision'], decision=choice,
                      rationale='依据当前冻结源码及已读记录逐项完成审查。') for i in batch['items']]
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='离线批次审查',
                               review_batch_id=batch['id'], review_decisions=decisions)
    return decisions


def test_exact_decisions_and_stale_versions_are_rejected_atomically(state):
    store, repo, run = state
    store.add_finding(_conclusion_finding(run))
    batch = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'])
    with pytest.raises(ValueError, match='恰好'):
        validate_batch(batch, [])
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    with pytest.raises(ValueError):
        store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='拒绝遗漏项',
                                   review_batch_id=batch['id'], review_decisions=[])
    assert store.active_review_batch(run['id'])['status'] == 'pending'
    assert not store._rows('SELECT * FROM audit_review_items', ())
    store._write("UPDATE findings SET summary='结论内容发生实质更新' WHERE run_id=?", (run['id'],))
    refreshed = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'])
    assert refreshed['id'] != batch['id']
    commit(store, run, refreshed)
    assert store.prepare_review_batch(run['id'], 'integration', run['execution_epoch']) is None


def test_completed_worker_direction_requires_batch_resolution(state):
    store, repo, run = state
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='派发窄任务',
                               tasks=[proposal('source-check')])
    task = store.claim_ready_task(run['id'], 'worker')
    direction_id = 'dir_' + 'a' * 32
    result = {'outcome':'no_evidence', 'summary':'原始源码已逐行检查，未发现额外问题。', 'reasoning':'读取入口原始行，参数经权限检查后传递。',
              'remaining_work':[], 'direction_results':[{'direction_id':direction_id,'outcome':'no_evidence','rationale':'已完成本次领取方向的源码核对。'}]}
    store.resolve_task_attempt(task['id'], 'worker', outcome='no_evidence', result=result, usage={},
                               seen=[{'path':'public/index.php','start_line':1,'end_line':4}], terminal_reason='completed')
    result['host_directions'] = [{'id':direction_id,'text':'public/index.php 输入校验复核','paths':['public/index.php'],
        'state':'assigned','assigned_task_key':task['task_key'],'origin_task_key':task['task_key'],'origin_task_id':task['id']}]
    store._write('UPDATE planner_tasks SET result=? WHERE id=?',(json.dumps(result),task['id']))
    assert store.audit_direction_summary(run['id'])['unsettled_total'] == 1
    batch = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'])
    commit(store, run, batch, 'resolve')
    assert store.audit_direction_summary(run['id'])['unsettled_total'] == 0
    assert store.prepare_review_batch(run['id'], 'integration', run['execution_epoch']) is None


def test_static_final_review_and_all_exports_are_immutable(state, tmp_path, monkeypatch):
    from audit import app as app_module
    store, repo, run = state
    store.add_finding(_conclusion_finding(run))
    integration = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'])
    commit(store, run, integration)
    store.set_workflow_stage(run['id'], 'review')
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    assert batch['items'][0]['evidence_complete']
    commit(store, run, batch, 'accept')
    assert store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo) is None
    store.terminate_execution(run['id'], 'inconclusive', {'code':'offline','message':'离线验收终态'},epoch=run['execution_epoch'])
    assert store.frozen_report(run['id'])['facts'] is None
    assert store.frozen_report(run['id'])['input']['frozen_source_evidence'][0]['available']
    def source_gone(*args):
        raise AssertionError('Rendering may only use frozen source bytes')
    monkeypatch.setattr(repo, 'read_source', source_gone)
    frozen = materialize(store, repo, run['id'])
    assert frozen['facts']['counts']['accepted'] == 1
    assert frozen['facts']['review_batch']['unresolved_items'] == []
    assert len(frozen['facts']['review_batch']['decisions']) == 1
    assert frozen['facts']['provenance']['immutable'] is True
    assert frozen['facts']['source_evidence'][0]['available']
    assert frozen['facts']['canonical_findings'][0]['frozen_claim']['verification_status'] != 'verified'
    state = SimpleNamespace(store=store, repository=repo, settings=SimpleNamespace(evidence_dir=tmp_path))
    monkeypatch.setattr(app_module.app.state, 'services', state, raising=False)
    client = TestClient(app_module.app)
    try:
        before = {fmt:client.get(f'/api/runs/{run["id"]}/report?format={fmt}').content for fmt in ('markdown','json','zip')}
        store._write("UPDATE findings SET summary='之后人工修改，不得进入旧报告',disposition='retracted' WHERE run_id=?", (run['id'],))
        after = {fmt:client.get(f'/api/runs/{run["id"]}/report?format={fmt}').content for fmt in before}
        assert before == after
        assert client.get(f'/api/runs/{run["id"]}/final-review').json()['counts']['accepted'] == 1
    finally:
        client.close()
    with pytest.raises(sqlite3.IntegrityError, match='immutable'):
        store._write("UPDATE frozen_run_reports SET input_json='{}' WHERE run_id=?", (run['id'],))
    with pytest.raises(sqlite3.IntegrityError, match='immutable'):
        store._write("UPDATE frozen_run_reports SET markdown='rewritten' WHERE run_id=?", (run['id'],))


def test_separate_attempt_quotas_share_the_original_run_counters(state):
    store, repo, run = state
    store.set_workflow_stage(run['id'], 'poc')
    scopes = [hashlib.sha256(value.encode()).hexdigest() for value in ('finding-a:v1','finding-b:v1')]
    gateways = [StorePocRequestGateway(store,scope=scope) for scope in scopes]
    for gateway in gateways:
        for stage,limit in [('conclude',3),('execute',1)]:
            assert gateway.open_stage(run_id=run['id'],epoch=run['execution_epoch'],stage=stage,limit=limit)['ok']
    first,second=gateways
    assert first.reserve(run_id=run['id'],epoch=run['execution_epoch'],stage='execute')['granted']
    assert not first.reserve(run_id=run['id'],epoch=run['execution_epoch'],stage='execute')['granted']
    assert second.reserve(run_id=run['id'],epoch=run['execution_epoch'],stage='execute')['granted']
    assert first.snapshot(run_id=run['id'],epoch=run['execution_epoch'])['execute']['remaining'] == 0
    assert store.execution_summary(run['id'])['run_usage']['responses'] == 2


def test_dynamic_confirmation_does_not_replace_the_independent_final_batch(state):
    from audit.final_review import canonical_groups
    store, repo, run = state
    finding = {**_conclusion_finding(run), 'verification_status':'verified',
               'latest_verification_id':'verification-one', 'verifications':[{'id':'verification-one'}],
               'verification_reviews':[{'revision':1,'verification_id':'verification-one','decision':'confirmed'}]}
    assert canonical_groups([finding])[0][0]['final_disposition'] == 'accepted'  # legacy semantics
    guarded = store.attach_final_decisions(run['id'], [finding])
    assert canonical_groups(guarded)[0][0]['final_disposition'] == 'pending'


@pytest.mark.parametrize('workflow', ['discovery_first', 'legacy'])
def test_coordinator_runs_integration_then_independent_final_batch_without_real_models(state, monkeypatch, workflow):
    import asyncio
    from audit import worker as worker_module
    from audit.execution_state import CURRENT_EXECUTION
    from tests.test_goal_tasks import make_worker, worker_outcome
    store, repo, run = state
    if workflow == 'legacy':
        task = {**run['task_spec'], 'workflow_policy':'legacy'}
        store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(task),run['id']))
        store._write("UPDATE run_execution_state SET workflow='{}' WHERE run_id=?", (run['id'],))
        run = store.get_run(run['id'])
    calls = []
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context'].get('review_batch')
        if batch:
            calls.append(batch['phase'])
            decisions = [dict(item_id=item['item_id'], revision=item['revision'],
                              decision='retain' if batch['phase']=='integration' else 'accept',
                              rationale='已对照宿主提供的原始源码与当前版本逐项判读。') for item in batch['items']]
            decision = dict(goal_state='continue',basis_summary='逐项结算领取项', review_batch_id=batch['id'],review_decisions=decisions)
        elif not store.list_tasks(run['id']):
            calls.append('planning')
            decision = dict(goal_state='continue',basis_summary='派发具体入口审计',tasks=[proposal('source-flow')])
        else:
            calls.append('closure')
            decision = dict(goal_state='met',basis_summary='已按证据完成当前任务。',tasks=[])
        return {'decision':decision,'usage':{'requests':1},'terminal_reason':'completed'}
    async def source(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        finding = {'title':'入口未约束路径进入文件操作','kind':'vulnerability','severity':'high',
                   'summary':'外部路径未经约束传入文件读取操作，能够越过预期目录。',
                   'vulnerability_type':'path_traversal','primary_location':{'path':'public/index.php','line':4},
                   'evidence':'public/index.php:4-4','dangerous_operation':'readfile of user-selected path'}
        return worker_outcome('achieved',finding=finding,seen=[{'path':'public/index.php','start_line':1,'end_line':4}])
    monkeypatch.setattr(worker_module,'plan_audit_frontier',planner)
    monkeypatch.setattr(worker_module,'pursue_planner_task',source)
    asyncio.run(make_worker(store,repo)._execute(run))
    final = store.get_run(run['id'])
    assert final['status'] in {'completed','inconclusive'}, final.get('error')
    assert 'integration' in calls and 'final' in calls, calls
    assert calls.index('integration') < calls.index('final')
    assert calls.count('integration') == calls.count('final') == 1
    assert store.frozen_report(run['id'])['facts'] is not None


def test_a_changed_final_rejection_earns_another_round(state, monkeypatch):
    """Two identical rejections stop the review; a changed one is progress.

    The real run ended its whole terminal review after two rejected rounds, one of
    which had already moved past the previous contract error.  This replays that
    shape: the first two final rounds are rejected for different reasons and the
    third publishes, so the batch must be settled rather than left pending.
    """
    import asyncio
    from audit import worker as worker_module
    from audit.execution_state import CURRENT_EXECUTION
    from tests.test_goal_tasks import make_worker, worker_outcome
    store, repo, run = state
    rejections = iter(['终审发布缺少 comparison_candidates 判读', '终审发布缺少 rationale_summary'])
    phases, final_rounds = [], 0

    async def planner(**kwargs):
        nonlocal final_rounds
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context'].get('review_batch')
        if batch:
            phases.append(batch['phase'])
            if batch['phase'] == 'final':
                final_rounds += 1
                reason = next(rejections, None)
                if reason:
                    return {'terminal_reason': 'invalid_output', 'error': reason}
            decisions = [dict(item_id=item['item_id'], revision=item['revision'],
                              decision='retain' if batch['phase'] == 'integration' else 'accept',
                              rationale='已对照宿主提供的原始源码与当前版本逐项判读。')
                         for item in batch['items']]
            decision = dict(goal_state='continue', basis_summary='逐项结算领取项',
                            review_batch_id=batch['id'], review_decisions=decisions)
        elif not store.list_tasks(run['id']):
            decision = dict(goal_state='continue', basis_summary='派发具体入口审计',
                            tasks=[proposal('source-flow')])
        else:
            decision = dict(goal_state='met', basis_summary='已按证据完成当前任务。', tasks=[])
        return {'decision': decision, 'usage': {'requests': 1}, 'terminal_reason': 'completed'}

    async def source(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        finding = {'title': '入口未约束路径进入文件操作', 'kind': 'vulnerability', 'severity': 'high',
                   'summary': '外部路径未经约束传入文件读取操作，能够越过预期目录。',
                   'vulnerability_type': 'path_traversal',
                   'primary_location': {'path': 'public/index.php', 'line': 4},
                   'evidence': 'public/index.php:4-4',
                   'dangerous_operation': 'readfile of user-selected path'}
        return worker_outcome('achieved', finding=finding,
                              seen=[{'path': 'public/index.php', 'start_line': 1, 'end_line': 4}])

    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    monkeypatch.setattr(worker_module, 'pursue_planner_task', source)
    asyncio.run(make_worker(store, repo)._execute(run))
    assert final_rounds == 3, final_rounds
    assert store.review_batches_pending(run['id'], 'final', repo) == []
    assert store.active_review_batch(run['id'], 'final') is None


def test_sdk_exhaustion_is_detected_before_any_target_action(state):
    import asyncio
    from audit.poc import PocPolicy, PocVerifier
    store, repo, run = state
    store.set_workflow_stage(run['id'], 'poc')
    finding = _conclusion_finding(run)
    policy = PocPolicy(runtime='claude_sdk', max_steps=8, max_responses=11)
    verifier = PocVerifier.__new__(PocVerifier)
    verifier.store = store
    verifier.bus = SimpleNamespace(emit=lambda *args:None)
    verifier._sdk_readiness = lambda *args, **kwargs:{'ready':True}
    assert verifier._sdk_quota_available(run,finding,policy)
    gateway = StorePocRequestGateway(store,scope=verifier._sdk_scope(run,finding))
    for _ in range(8):
        assert gateway.reserve(run_id=run['id'],epoch=run['execution_epoch'],stage='execute')['granted']
    class NoTargetActions:
        def __getattr__(self,name):
            raise AssertionError('No reset/context/identity action may run: '+name)
    result, reason, record, artifacts, jobs = asyncio.run(verifier.verify_finding(
        run,finding,policy,{},NoTargetActions(),model_config=None))
    assert reason == 'quota_deferred' and record == {} and not jobs
