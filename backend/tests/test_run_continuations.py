"""Continuation contracts on isolated SQLite; never uses a real runner or provider."""
import asyncio
import copy
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from audit import agent, app as app_module, worker as worker_module
from audit.execution_state import CURRENT_EXECUTION
from audit.frozen_reports import materialize
from audit.poc import _pin_sdk_requests
from audit.runtimes.claude_poc import ClaudePocLimits
from audit.schemas import ContinueRunRequest
from tests.test_host_queue import hosted, add_claim, submit, completed_task_with_direction  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_goal_tasks import make_worker
from tests.test_recent_closure_repair import failed_finding
from tests.test_review_input_repair import decisions
from tests.code_model import ModelFactory, CONFIG, code, transcript
from audit.runtime import AgentPolicy


def finish(store, run):
    store.terminate_execution(run['id'], 'inconclusive', {'code': 'offline_partial', 'message': '离线验收保留部分成果'}, epoch=run['execution_epoch'])
    store.quiesce_execution(run['id'])


def request(**kwargs):
    return ContinueRunRequest(request_id='test-continuation', **kwargs).model_dump()


def test_clones_evidence_and_history_with_new_budget_without_mutating_parent(hosted):
    store, repo, run = hosted
    finding = add_claim(store, run, 1, verified=True)
    completed_task_with_direction(store, run, required=True)
    finish(store, run)
    before = store.frozen_report(run['id'])['input_json']
    usage = copy.deepcopy(store.execution_summary(run['id'])['run_usage'])
    child = store.create_continuation(run['id'], request(mode='review'))
    assert child['id'] != run['id'] and child['status'] == 'pending'
    assert child['snapshot_id'] == run['snapshot_id']
    assert child['execution_summary']['run_limits']['responses'] == 256
    assert child['execution_summary']['run_usage']['responses'] == 0
    assert child['execution_summary']['workflow']['stage'] == 'review'
    assert len(store.list_tasks(child['id'])) == len(store.list_tasks(run['id']))
    assert store.audit_direction_summary(child['id'])['unsettled_total'] == 1
    copied = store.list_findings(child['id'])[0]
    assert copied['id'] != finding['id'] and copied['revision'] == finding['revision']
    assert copied['verification_status'] == 'verified'
    v = store.list_verifications(copied['id'])[0]
    assert v['agent']['continuation_source']['run_id'] == run['id']
    assert v['agent']['jobs'] == finding['verifications'][0]['agent']['jobs']
    assert store.frozen_report(run['id'])['input_json'] == before
    assert store.execution_summary(run['id'])['run_usage'] == usage
    assert not store._rows('SELECT * FROM poc_attempts WHERE run_id=?', (child['id'],))


def test_clone_does_not_rewrite_json_observations_or_raw_outputs_containing_old_ids(hosted):
    store, _, run = hosted
    finding = add_claim(store, run, 1, verified=True)
    v = store.list_verifications(finding['id'])[0]
    observation = json.dumps({'finding_id': finding['id'], 'run_id': run['id'], 'verification_id': v['id']})
    v['agent']['job_results'] = [{'job_id': 'original-job', 'context_id': 'original-context',
                                 'result': {'stdout': finding['id'], 'body': observation}}]
    store._write('UPDATE verifications SET normal_observation=?,agent=? WHERE id=?', (observation, json.dumps(v['agent']), v['id']))
    finish(store, run)
    child = store.create_continuation(run['id'], request(mode='review'))
    copied = store.list_findings(child['id'])[0]
    new_v = store.list_verifications(copied['id'])[0]
    assert new_v['normal_observation'] == observation
    assert new_v['agent']['job_results'] == v['agent']['job_results']
    assert new_v['agent']['continuation_source']['verification_id'] == v['id']
    store.claim_next_run()
    store.terminate_execution(child['id'], 'inconclusive', {'code': 'offline'}, epoch=store.get_run(child['id'])['execution_epoch'])
    report = materialize(store, store._report_repository, child['id'])
    assert report['facts']['verification_attempts'][0]['inherited_from']['verification_id'] == v['id']
    assert '继承验证' in report['markdown']


def test_request_is_idempotent_but_changed_budget_and_parallel_children_are_rejected(hosted):
    store, _, run = hosted
    add_claim(store, run, 1)
    finish(store, run)
    payload = request()
    first = store.create_continuation(run['id'], payload)
    assert store.create_continuation(run['id'], payload)['id'] == first['id']
    assert store.continuation_options(run['id'])['continuations'][0]['id'] == first['id']
    with pytest.raises(ValueError, match='相同 request_id'):
        store.create_continuation(run['id'], request(run_limits=dict(responses=512, tools=4096, seconds=3600)))
    other = {**payload, 'request_id': 'another-request'}
    with pytest.raises(ValueError, match='尚未结束'):
        store.create_continuation(run['id'], other)
    assert len(store.list_runs()) == 2


def test_completed_accepted_peer_is_carried_but_selected_claim_is_reopened(hosted):
    store, repo, run = hosted
    good = add_claim(store, run, 1, verified=True)
    pending = add_claim(store, run, 2)
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    submit(store, run, batch)
    finish(store, run)
    child = store.create_continuation(run['id'], request(finding_ids=[pending['id']]))
    from audit.final_review import canonical_groups
    entries, _ = canonical_groups(store.attach_final_decisions(child['id'], store.list_findings(child['id'])))
    assert sorted(e['final_disposition'] for e in entries) == ['accepted', 'pending']
    carried = next(e for e in entries if e['final_disposition'] == 'accepted')
    assert carried['final_batch_review']['inherited_from_run_id'] == run['id']
    assert child['task_spec']['continuation']['source_refs'][carried['frozen_claim']['finding_id']] == good['id']


def test_failed_setup_rolls_back_the_entire_child(hosted, monkeypatch):
    store, _, run = hosted
    add_claim(store, run, 1)
    finish(store, run)
    def failed(*args):
        raise ValueError('simulated setup failure')
    monkeypatch.setattr(store, '_review_candidates', failed)
    with pytest.raises(ValueError, match='setup failure'):
        store.create_continuation(run['id'], request())
    assert len(store.list_runs()) == 1
    assert store._row('SELECT COUNT(*) FROM findings')[0] == 1


def test_retesting_a_related_claim_reopens_its_previously_accepted_peer(hosted):
    store, repo, run = hosted
    good = add_claim(store, run, 1, verified=True)
    pending = add_claim(store, run, 2)
    store._write("UPDATE findings SET vulnerability_type='session_fixation',primary_location=? WHERE run_id=?", (json.dumps({'path': 'public/index.php', 'line': 4}), run['id']))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    assert all(i['payload']['comparison_candidates'] for i in batch['items'])
    def distinguish(decisions, reviews):
        for d in decisions:
            d['distinct_from'] = [i['item_id'] for i in batch['items'] if i['item_id'] != d['item_id']]
    submit(store, run, batch, invalid=distinguish)
    finish(store, run)
    child = store.create_continuation(run['id'], request(finding_ids=[pending['id']]))
    assert store._row('SELECT COUNT(*) FROM audit_review_items WHERE run_id=?', (child['id'],))[0] == 0
    assert sum(map(len, store.review_batches_pending(child['id'], 'final', repo))) == 2


def test_no_unknown_confirmed_or_withdrawn_finding_can_be_retested(hosted):
    store, _, run = hosted
    verified = add_claim(store, run, 1, verified=True)
    other = add_claim(store, run, 2)
    store._write("UPDATE findings SET disposition='duplicate' WHERE id=?", (other['id'],))
    finish(store, run)
    for ids in [['unknown'], [verified['id']], [other['id']]]:
        with pytest.raises(ValueError, match='未决'):
            store.create_continuation(run['id'], request(finding_ids=ids))
    with pytest.raises(ValueError, match='没有选中'):
        store.create_continuation(run['id'], request(finding_ids=[]))
    assert len(store.list_runs()) == 1


def test_selected_retest_preserves_successful_peer_and_sdk_time_limit(hosted):
    store, _, run = hosted
    good = add_claim(store, run, 1, verified=True)
    pending = add_claim(store, run, 2)
    finish(store, run)
    child = store.create_continuation(run['id'], request(finding_ids=[pending['id']], poc=dict(max_seconds=900, execute_requests=80)))
    continuation = child['task_spec']['continuation']
    assert len(continuation['retest_finding_ids']) == 1
    assert continuation['source_refs'][continuation['retest_finding_ids'][0]] == pending['id']
    assert good['id'] in continuation['source_refs'].values()
    limits = _pin_sdk_requests(ClaudePocLimits(), child['poc_policy']['sdk_requests'])
    assert limits.max_seconds == 900 and limits.execute_requests == 80
    assert sum(child['execution_summary']['workflow']['limits'].values()) == child['run_limits']['responses']


def test_review_only_uses_existing_worker_and_never_calls_poc(hosted, monkeypatch):
    store, repo, run = hosted
    add_claim(store, run, 1)
    finish(store, run)
    original = store.frozen_report(run['id'])['input_json']
    child = store.create_continuation(run['id'], request(mode='review'))
    claimed = store.claim_next_run()
    assert claimed['id'] == child['id']
    calls = []
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context']['review_batch']
        calls.append(batch['phase'])
        return dict(decision=dict(goal_state='continue', basis_summary='只读既有证据并逐项终审。',
            review_batch_id=batch['id'], review_decisions=decisions(batch, 'accept')),
            usage={'requests': 1}, terminal_reason='completed')
    async def forbidden(*args, **kwargs):
        pytest.fail('review-only must never execute a POC')
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    monkeypatch.setattr(worker_module.PocVerifier, 'verify_standing', forbidden)
    asyncio.run(make_worker(store, repo)._execute(claimed))
    result = store.get_run(child['id'])
    assert result['status'] in {'completed', 'inconclusive'}, result.get('error')
    assert calls == ['final']
    facts = materialize(store, repo, child['id'])['facts']
    assert facts['counts']['accepted'] == 1
    assert facts['provenance']['continuation']['parent_run_id'] == run['id']
    assert store.frozen_report(run['id'])['input_json'] == original


def test_coordinator_retests_only_selected_subjects(hosted, monkeypatch):
    store, repo, run = hosted
    add_claim(store, run, 1, verified=True)
    pending = add_claim(store, run, 2)
    store._write("UPDATE runs SET project_mode='project' WHERE id=?", (run['id'],))
    finish(store, run)
    child = store.create_continuation(run['id'], request(finding_ids=[pending['id']]))
    claimed = store.claim_next_run()
    tested = []
    async def verify(verifier, run_id, findings, verified_for, **kwargs):
        tested.extend(f['id'] for f in findings)
        for finding in findings:
            verified_for[finding.get('project_finding_id') or finding['id']] = finding.get('project_revision') or finding.get('revision') or 1
        return dict(processed=len(findings), remaining=0)
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context']['review_batch']
        assert batch['phase'] == 'final'
        return dict(decision=dict(goal_state='continue', basis_summary='保留缺少动态对照的未决结论。',
            review_batch_id=batch['id'], review_decisions=decisions(batch, 'needs_evidence')),
            usage={'requests': 1}, terminal_reason='completed')
    monkeypatch.setattr(worker_module.PocVerifier, 'verify_standing', verify)
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    asyncio.run(make_worker(store, repo)._execute(claimed))
    assert tested == child['task_spec']['continuation']['retest_finding_ids']
    assert store.get_run(child['id'])['status'] == 'inconclusive'


def test_static_acceptance_does_not_hide_requested_but_unresolved_poc(hosted, monkeypatch):
    store, repo, run = hosted
    add_claim(store, run, 1)
    store._write("UPDATE runs SET project_mode='project' WHERE id=?", (run['id'],))
    store.append_event(run['id'], None, 'coverage_review_recorded', {'paths': [
        {'path': p, 'reason': '离线验证仅复核已有结论，明确保留其余模块未审限制。', 'action': 'skip'} for p in run['scope']]})
    finish(store, run)
    child = store.create_continuation(run['id'], request())
    claimed = store.claim_next_run()
    async def verify(verifier, run_id, findings, verified_for, **kwargs):
        for finding in findings:
            verified_for[finding.get('project_finding_id') or finding['id']] = finding.get('project_revision') or finding.get('revision') or 1
        return dict(processed=len(findings), remaining=0)
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context']['review_batch']
        return dict(decision=dict(goal_state='continue', basis_summary='源码证据充分，静态接受但未完成动态验证。',
            review_batch_id=batch['id'], review_decisions=decisions(batch, 'accept')),
            usage={'requests': 1}, terminal_reason='completed')
    monkeypatch.setattr(worker_module.PocVerifier, 'verify_standing', verify)
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    asyncio.run(make_worker(store, repo)._execute(claimed))
    final = store.get_run(child['id'])
    assert final['status'] == 'inconclusive', final
    assert final['execution_summary']['stop_reason']['code'] == 'poc_unresolved'
    assert materialize(store, repo, child['id'])['facts']['counts']['accepted'] == 1


def test_pausing_a_continuation_preserves_added_budget_and_selection(hosted):
    store, _, run = hosted
    add_claim(store, run, 1)
    finish(store, run)
    child = store.create_continuation(run['id'], request())
    claimed = store.claim_next_run()
    store.admit_execution(child['id'], claimed['execution_epoch'], 'responses')
    store.request_pause(child['id'])
    store.quiesce_execution(child['id'])
    assert store.resume_run(child['id'])
    resumed = store.claim_next_run()
    assert resumed['execution_summary']['run_usage']['responses'] == 1
    assert resumed['run_limits'] == child['run_limits']
    assert resumed['task_spec']['continuation'] == child['task_spec']['continuation']


def test_source_continuation_requeues_blocked_work_without_erasing_prior_attempts(hosted):
    store, repo, run = hosted
    completed_task_with_direction(store, run, required=True)
    task = store.list_tasks(run['id'])[0]
    store._write("UPDATE planner_tasks SET state='blocked' WHERE id=?", (task['id'],))
    finish(store, run)
    child = store.create_continuation(run['id'], request(mode='audit', finding_ids=[]))
    copied = store.list_tasks(child['id'])[0]
    assert copied['state'] == 'ready'
    assert copied['attempts'] == task['attempts']
    assert copied['max_attempts'] > copied['attempts']
    assert child['execution_summary']['workflow']['stage'] == 'discovery'
    assert store.planner_coverage(child['id'])['read_paths'] == store.planner_coverage(run['id'])['read_paths']
    assert store.audit_direction_summary(child['id'])['unsettled_total'] == 1


@pytest.mark.parametrize('change', ['new', 'revised'])
def test_resume_does_not_mistake_new_or_revised_work_for_an_inherited_verdict(hosted, monkeypatch, change):
    store, repo, run = hosted
    add_claim(store, run, 1, verified=True)
    store._write("UPDATE runs SET project_mode='project' WHERE id=?", (run['id'],))
    finish(store, run)
    child = store.create_continuation(run['id'], request(mode='audit', finding_ids=[]))
    claimed = store.claim_next_run()
    if change == 'new':
        changed = add_claim(store, claimed, 2)
    else:
        changed = store.list_findings(child['id'])[0]
        store._write("UPDATE findings SET revision=revision+1,verification_status='stale' WHERE id=?", (changed['id'],))
    store.set_workflow_stage(child['id'], 'poc', reason={'state': 'inconclusive', 'basis': '离线模拟暂停前的源码阶段已停止。'})
    store.request_pause(child['id']); store.quiesce_execution(child['id'])
    assert store.resume_run(child['id'])
    resumed = store.claim_next_run()
    tested = []
    async def verify(verifier, run_id, findings, verified_for, **kwargs):
        tested.extend(f['id'] for f in findings)
        for f in findings:
            verified_for[f.get('project_finding_id') or f['id']] = f.get('project_revision') or f.get('revision') or 1
        return dict(processed=len(findings), remaining=0)
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context']['review_batch']
        return dict(decision=dict(goal_state='continue', basis_summary='新增或修订结论需要进一步核实。',
            review_batch_id=batch['id'], review_decisions=decisions(batch, 'needs_evidence')),
            usage={'requests': 1}, terminal_reason='completed')
    monkeypatch.setattr(worker_module.PocVerifier, 'verify_standing', verify)
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    asyncio.run(make_worker(store, repo)._execute(resumed))
    assert tested == [changed['id']]
    assert store.pending_continuation_verifications(child['id']) == [changed['id']]


def test_mandatory_reads_cannot_consume_the_publication_request(hosted, monkeypatch):
    store, repo, run = hosted
    failed_finding(store, run)
    store.set_workflow_stage(run['id'], 'review')
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    read = f"""
import json
for part in {item['paged_fields']!r}:
    offset = 0
    while offset is not None:
        page = json.loads(read_review_input({item['item_id']!r}, part['field'], offset))
        print(page['text'])
        offset = page['next_offset']
"""
    answer = dict(goal_state='continue', basis_summary='原作业存在，缺少完整攻击对照，明确保留存疑。',
                  review_batch_id=batch['id'], review_decisions=decisions(batch, 'contested'))
    factory = ModelFactory({'planner_decision': [code(read), 'missing action block'],
                            'planner_publish': [json.dumps(answer, ensure_ascii=False)]})
    monkeypatch.setattr(agent, 'build_code_model', factory)
    context = {**store.list_planner_context(run['id'], project_map=store.get_project_map(run['id'])), 'review_batch': batch}
    result = asyncio.run(agent.plan_audit_frontier(project_map=store.get_project_map(run['id']), run_context=context,
        task=run['task_spec'], round_no=1, config=CONFIG, budgets=dict(responses=3, tools=100, seconds=10),
        policy=AgentPolicy(request_seconds=.5), repository=repo, snapshot_id=run['snapshot_id'],
        allowed_paths=set(run['scope']), pins=store, run_id=run['id']))
    assert result['decision'], result
    assert result['usage']['requests'] == 3
    assert factory.phases[-1] == 'planner_publish'
    assert 'NORMAL_PAGE original body' in factory.prompts[-1]


def test_api_preview_and_create_are_explicit_and_validate_budgets(hosted, monkeypatch):
    store, repo, run = hosted
    add_claim(store, run, 1)
    finish(store, run)
    notified = []
    services = SimpleNamespace(store=store, repository=repo, settings=SimpleNamespace(model=CONFIG),
                               worker=SimpleNamespace(notify=lambda: notified.append(True)))
    monkeypatch.setattr(app_module.app.state, 'services', services, raising=False)
    client = TestClient(app_module.app)
    try:
        assert client.get(f'/api/runs/{run["id"]}/continuation').json()['retestable_count'] == 1
        assert not notified and len(store.list_runs()) == 1
        assert client.get('/api/runs/missing/continuation').status_code == 404
        assert client.post(f'/api/runs/{run["id"]}/continuation', json={'request_id': 'invalid-budget', 'run_limits': {'responses': True}}).status_code == 422
        response = client.post(f'/api/runs/{run["id"]}/continuation', json=request())
        assert response.status_code == 201, response.text
        assert notified == [True]
    finally:
        client.close()


def test_continuation_uses_selected_profile_unless_original_is_explicit(hosted, monkeypatch):
    from audit.config import ModelConfig
    store, repo, run = hosted
    add_claim(store, run, 1)
    finish(store, run)
    original = copy.deepcopy(store.get_run(run['id'])['model_profile'])
    profile = store.create_model_profile(label='新的终审模型', model='new-review-model',
        base_url='https://review.invalid/v1', api_key_secret='offline-cipher')
    store.select_model_profile(profile['id'])
    services = SimpleNamespace(store=store, repository=repo,
        model_config_for_profile=lambda p: ModelConfig(model=p['model'], base_url=p['base_url'], api_key='offline'),
        worker=SimpleNamespace(notify=lambda: None))
    monkeypatch.setattr(app_module.app.state, 'services', services, raising=False)
    client = TestClient(app_module.app)
    try:
        preview = client.get(f'/api/runs/{run["id"]}/continuation').json()
        assert preview['selected_profile_id'] == profile['id']
        assert 'api_key_secret' not in json.dumps(preview)
        response = client.post(f'/api/runs/{run["id"]}/continuation', json=request(mode='review'))
        assert response.status_code == 201, response.text
        child = response.json()
        assert child['model'] == 'new-review-model'
        assert child['model_profile']['profile_id'] == profile['id']
        assert store.get_run(run['id'])['model_profile'] == original
        store.claim_next_run()
        finish(store, store.get_run(child['id']))
        response = client.post(f'/api/runs/{run["id"]}/continuation',
            json={**request(mode='review', model_profile_id='original'), 'request_id': 'explicit-old-profile'})
        assert response.status_code == 201, response.text
        assert response.json()['model_profile'] == original
    finally:
        client.close()


def test_continuation_rejects_unknown_profile_without_creating_run(hosted, monkeypatch):
    store, _, run = hosted
    add_claim(store, run, 1)
    finish(store, run)
    monkeypatch.setattr(app_module.app.state, 'services', SimpleNamespace(store=store), raising=False)
    client = TestClient(app_module.app)
    try:
        response = client.post(f'/api/runs/{run["id"]}/continuation', json=request(model_profile_id='missing'))
        assert response.status_code == 409
        assert len(store.list_runs()) == 1
    finally:
        client.close()


def test_sdk_derives_redundant_jobs_from_resolved_normal_and_attack_refs(tmp_path):
    from audit.runtimes.claude_poc import ClaudeCodePocRuntime, EvidenceRefTable, MemoryPocRequestGateway
    from audit.poc_agent import evidence_errors
    from tests.test_claude_poc_runtime import service, http_job
    deps = service(tmp_path, jobs=[http_job('normal', body='normal member'), http_job('attack', body='attack admin')])
    refs = EvidenceRefTable.build(deps)
    by_job = {ref.job_id: ref for ref in refs._refs.values() if ref.channel == 'body'}
    runtime = ClaudeCodePocRuntime(limits=ClaudePocLimits(), gateway=MemoryPocRequestGateway())
    runtime._service = deps
    result, errors = runtime._build_result(dict(status='verified', summary='有明确的正常攻击对照',
        jobs=['attack'], normal_observation='normal member', attack_observation='attack admin',
        normal_refs=[by_job['normal'].ref_id], attack_refs=[by_job['attack'].ref_id]), refs)
    assert not errors
    assert result.jobs == ['attack', 'normal']
    assert not evidence_errors(result, deps)
