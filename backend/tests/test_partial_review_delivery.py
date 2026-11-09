"""c07721af: one stalled final item must not suppress other confirmed reports."""
import asyncio
import copy
import io
import json
import zipfile

import pytest

from audit import agent
from audit import worker as worker_module
from audit.execution_state import CURRENT_EXECUTION
from audit.final_review import canonical_groups
from audit.report_readable import document, export
from audit.review_policy import batch_response_reserve, validate_peer_assessments
from audit.runtime import AgentPolicy
from tests.code_model import CONFIG, ModelFactory, code
from tests.test_host_queue import hosted, add_claim, submit  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_recent_closure_repair import failed_finding
from tests.test_report_delivery import frozen_report, client  # noqa: F401
from tests.test_goal_tasks import make_worker, proposal, worker_outcome


def test_stuck_multi_item_batch_splits_and_single_failure_does_not_starve_other_items(hosted):
    store, repo, run = hosted
    for index in range(3):
        add_claim(store, run, index)
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    assert len(batch['items']) == 3
    usage = copy.deepcopy(store.execution_summary(run['id'])['run_usage'])
    store.defer_review_batch(run['id'], batch['id'], '模拟多项批次持续拒绝', split=True)
    single = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    assert len(single['items']) == 1
    blocked = single['items'][0]['item_id']
    store.defer_review_batch(run['id'], single['id'], '单项纠正仍未通过，保持待审')
    completed = []
    while (next_batch := store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)):
        assert len(next_batch['items']) == 1
        assert next_batch['items'][0]['item_id'] != blocked
        completed.append(next_batch['items'][0]['item_id'])
        submit(store, run, next_batch)
    assert len(completed) == 2
    unresolved = store.review_batches_pending(run['id'], 'final', repo)
    assert [item['item_id'] for group in unresolved for item in group] == [blocked]
    assert store.review_batches_pending(run['id'], 'final', repo, for_scheduling=True) == []
    actual_usage = store.execution_summary(run['id'])['run_usage']
    assert (actual_usage['responses'], actual_usage['tools']) == (usage['responses'], usage['tools'])
    assert actual_usage['seconds'] >= usage['seconds']
    assert not store._row("SELECT 1 FROM audit_review_items WHERE run_id=? AND phase='final' AND item_id=?", (run['id'], blocked))
    # Deferral is not a new verdict; a new execution epoch may review it again.
    store._write('UPDATE run_execution_state SET claim_epoch=claim_epoch+1 WHERE run_id=?', (run['id'],))
    next_run = store.get_run(run['id'])
    resumed = store.prepare_review_batch(run['id'], 'final', next_run['execution_epoch'], repo)
    assert resumed['items'][0]['item_id'] == blocked


def test_paged_reader_can_publish_and_correct_without_spending_its_last_request_on_reading(hosted, monkeypatch):
    store, repo, run = hosted
    failed_finding(store, run)
    store.set_workflow_stage(run['id'], 'review')
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    body = f"""
import json
for part in {item['paged_fields']!r}:
    offset = 0
    while offset is not None:
        page = json.loads(read_review_input({item['item_id']!r}, part['field'], offset))
        print(page['text'])
        offset = page['next_offset']
"""
    request = dict(goal_state='continue', basis_summary='完整读取保存作业后保留攻击影响存疑。', review_batch_id=batch['id'],
                   review_decisions=[dict(item_id=item['item_id'], revision=item['revision'], decision='contested',
                                          rationale='已读取实际正常侧作业，攻击影响仍缺少充分证据。')])
    factory = ModelFactory({'planner_decision': [code("print('先检查批次中的真实字段和读取清单')"), code(body)],
                            'planner_publish': [json.dumps({'basis_summary': '短'}), json.dumps(request, ensure_ascii=False)]})
    monkeypatch.setattr(agent, 'build_code_model', factory)
    context = {**store.list_planner_context(run['id'], project_map=store.get_project_map(run['id'])), 'review_batch': batch}
    outcome = asyncio.run(agent.plan_audit_frontier(
        project_map=store.get_project_map(run['id']), run_context=context, task=run['task_spec'], round_no=1,
        config=CONFIG, budgets={'responses':24, 'tools':96, 'seconds':10}, policy=AgentPolicy(request_seconds=.5),
        repository=repo, snapshot_id=run['snapshot_id'], allowed_paths=set(run['scope']), pins=store, run_id=run['id']))
    assert outcome['decision'], outcome
    assert outcome['usage']['requests'] == 4
    assert batch_response_reserve([item]) == 5
    assert batch_response_reserve([{'paged_fields': []}]) == 3


def test_explicit_same_root_cannot_be_disguised_as_distinct_by_filling_all_ids():
    current = {'a': {'payload': {'comparison_candidates': [{'item_id':'b', 'finding_id':'run-b'}]}}}
    decision = dict(item_id='a', decision='accept', distinct_from=['b'],
                    comparison_assessments=[dict(item_id='b', relation='same_root', rationale='相同参数在相同危险操作与相同权限前提下触发。')])
    with pytest.raises(ValueError, match='same_root'):
        validate_peer_assessments([decision], current)
    decision['comparison_assessments'][0]['relation'] = 'distinct'
    validate_peer_assessments([decision], current)
    decision.update(decision='duplicate', duplicate_of='b')
    with pytest.raises(ValueError, match='same_root'):
        validate_peer_assessments([decision], current)
    decision['comparison_assessments'][0]['relation'] = 'same_root'
    validate_peer_assessments([decision], current)
    decision['comparison_assessments'][0]['item_id'] = 'run-b'
    with pytest.raises(ValueError, match='规范 item_id'):
        validate_peer_assessments([decision], current)


def test_real_coordinator_finishes_other_final_items_after_a_repeated_rejection(hosted, monkeypatch):
    store, repo, run = hosted
    failed_item = [None]
    attempts = {}
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context'].get('review_batch')
        if batch:
            if batch['phase'] == 'final':
                failed_item[0] = failed_item[0] or batch['items'][0]['item_id']
                if any(item['item_id'] == failed_item[0] for item in batch['items']):
                    attempts[batch['id']] = attempts.get(batch['id'], 0) + 1
                    return {'terminal_reason':'invalid_output', 'error':'固定重放：同一项的提交格式始终错误'}
            value = dict(goal_state='continue', basis_summary='完整检查本批的精确版本并逐项结算。', review_batch_id=batch['id'],
                         review_decisions=[dict(item_id=i['item_id'], revision=i['revision'],
                                                decision='accept' if batch['phase']=='final' else 'retain',
                                                rationale='冻结的输入到危险操作链有完整实际源码依据。') for i in batch['items']])
        elif not store.list_tasks(run['id']):
            value = dict(goal_state='continue', basis_summary='派发独立的源码路径调查。', tasks=[proposal('source-flow')])
        else:
            gaps = store.coverage_review(run['id']) or {}
            value = dict(goal_state='met', basis_summary='已保存当前已执行方向的证据结论。', tasks=[],
                         coverage_review=[dict(path=p, action='skip', reason='离线回放不执行该辅助路径，明确保留范围限制。') for p in gaps.get('pending_paths',[])])
        return {'decision':value, 'usage':{'requests':1}, 'terminal_reason':'completed'}
    async def source(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        findings = [dict(title=f'入口 {line} 未约束路径进入危险操作', kind='vulnerability', severity='high',
                         summary='外部路径未经边界检查进入文件操作，当前源码具备完整证据链。', vulnerability_type='path_traversal',
                         primary_location=dict(path='public/index.php',line=line), evidence=f'public/index.php:{line}-{line}',
                         dangerous_operation=f'file operation at original line {line}') for line in (1,2,4)]
        value = worker_outcome('achieved', finding=findings[0], seen=[dict(path='public/index.php',start_line=1,end_line=4)])
        value['result']['findings'] = findings
        return value
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    monkeypatch.setattr(worker_module, 'pursue_planner_task', source)
    asyncio.run(make_worker(store, repo)._execute(run))
    result = store.get_run(run['id'])
    entries, _ = canonical_groups(store.attach_final_decisions(run['id'], store.list_findings(run['id'])))
    assert result['status'] == 'inconclusive'
    assert sum(e['final_disposition']=='accepted' for e in entries) == 2
    assert sum(e['final_disposition']=='pending' for e in entries) == 1
    assert all(count <= 2 for count in attempts.values())  # Each failed round already spent its publication corrections.
    assert len(attempts) == 2  # The multi-item lease and the one isolated failing item.
    assert result['execution_summary']['stop_reason']['code'] == 'final_review_incomplete'


@pytest.mark.parametrize('format', ['markdown', 'json', 'zip'])
def test_confirmed_findings_form_an_independent_report_despite_pending_parent(format):
    saved = frozen_report()
    saved['input']['run']['status'] = 'inconclusive'
    saved['facts']['run_outcome']['audit_complete'] = False
    saved['facts']['action_items'] = [dict(object='other', title='PENDING_PRIVATE_BODY', action='PENDING_PRIVATE_ACTION')]
    saved['facts']['risk_obligations'] = dict(items=[dict(description='OUTSIDE_PRIVATE_RISK')])
    before = copy.deepcopy(saved)
    doc = document(saved, view='accepted')
    assert doc['counts'] == dict(canonical=1, accepted=1, pending=0, contested=0)
    assert doc['parent_summary']['counts']['pending'] == 1
    assert doc['scope']['canonical_ids'] == ['first']
    assert 'other' not in doc['numbering']
    assert doc['action_items'] == [] and doc['risk_obligations'] is None
    assert 'PENDING_PRIVATE_BODY' not in json.dumps(doc) and 'OUTSIDE_PRIVATE_RISK' not in json.dumps(doc)
    content = export(saved, view='accepted', format=format)
    assert content == export(saved, view='accepted', format=format)
    if format == 'markdown':
        assert '本报告不代表整次穷尽审计完成' in content.decode()
    elif format == 'json':
        assert json.loads(content)['render_quality']['passed']
    else:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            manifest = json.loads(archive.read('manifest.json'))
            assert manifest['main_document'] == 'accepted-findings.md'
            assert 'accepted-facts.json' in archive.namelist()
            assert 'final-review.json' not in archive.namelist()
            assert 'vulnerability-report.md' not in archive.namelist()
            assert len([name for name in archive.namelist() if name.startswith('findings/')]) == 1
            scoped = json.loads(archive.read('accepted-facts.json'))
            assert scoped['scope']['canonical_ids'] == ['first']
            assert json.loads(archive.read('render-quality.json'))['passed']
    assert saved == before


def test_no_confirmed_findings_do_not_turn_verified_pending_items_into_accepted(client):
    http, saved = client
    for entry in saved['facts']['canonical_findings']:
        entry['final_disposition'] = 'pending'
        entry['frozen_claim']['verification_status'] = 'verified'
    response = http.get('/api/runs/run-1/report?view=accepted&format=json')
    assert response.status_code == 200
    assert response.json()['counts']['accepted'] == 0
    assert response.json()['canonical_findings'] == []


def test_new_peer_policy_survives_report_quality_checks_without_reinterpreting_history():
    from audit.report_quality import evaluate
    from audit.review_policy import COMPARISON_POLICY
    saved = frozen_report()
    entry = saved['facts']['canonical_findings'][0]
    entry['comparison_candidates'] = [{'item_id':'other'}]
    entry['final_batch_review'].update(input_policy='paged-facts-v2', distinct_from=['other'])
    assert 'comparison_candidates_adjudicated' not in evaluate(saved['facts'])['failed_checks']
    entry['final_batch_review'].update(comparison_policy=COMPARISON_POLICY,
        comparison_assessments=[dict(item_id='other',relation='same_root',rationale='相同的输入参数通过相同的危险操作且前提完全一致。')])
    assert 'comparison_candidates_adjudicated' in evaluate(saved['facts'])['failed_checks']
    entry['final_batch_review']['comparison_assessments'][0]['relation'] = 'distinct'
    assert 'comparison_candidates_adjudicated' not in evaluate(saved['facts'])['failed_checks']


def test_explicit_scenario_skips_unrelated_poc_before_any_environment_or_model_action(tmp_path):
    from audit.capability import POLICY, POC_SCOPE_POLICY, poc_in_focus
    from audit.poc import PocVerifier
    from tests.test_poc_agent import FINDING, FakeStore, FakeBus, settings
    run = dict(id='run-1', project_id='project-1', project_mode='project', target_profile='lab30',
               poc_policy=dict(mode='auto', enabled=True),
               task_spec=dict(capability_policy=POLICY, poc_scope_policy=POC_SCOPE_POLICY, scenario='sqli',focus_scope='targeted'))
    finding = dict(copy.deepcopy(FINDING), vulnerability_type='command_injection')
    store, bus = FakeStore(run), FakeBus()
    class NoReadiness:
        async def check(self, *args, **kwargs):
            pytest.fail('Out-of-scenario candidates must not request environment readiness')
    def no_runner():
        pytest.fail('Out-of-scenario candidates must not create a runner')
    verifier = PocVerifier(store=store,bus=bus,settings=settings(tmp_path),client_factory=no_runner,readiness=NoReadiness())
    for _ in range(2):
        summary = asyncio.run(verifier.verify_standing('run-1',[finding],{},model_config=CONFIG))
        assert summary['outside_focus'] == 1 and summary['attempted'] == 0 and summary['remaining'] == 0
    assert len(bus.events) == 1 and bus.events[0][2]['reason'] == 'outside_focus'
    assert store.records == [] and store.jobs == []
    assert finding['vulnerability_type'] == 'command_injection'
    assert poc_in_focus(run,dict(finding,vulnerability_type='unknown'))
    assert poc_in_focus(run,dict(finding,vulnerability_type='sqli'))
    assert poc_in_focus({**run,'task_spec':{}},finding)  # Historical policy remains unchanged.
    retest = copy.deepcopy(run)
    retest['task_spec']['continuation'] = dict(retest_finding_ids=[finding['id']])
    assert poc_in_focus(retest,finding)
    helper = dict(finding, evidence=[dict(path='helper.php',start_line=2,end_line=5)])
    helper['focus'] = dict(objective_ref='objective-main',relation='supporting',supports=['sqli-main'],
                           rationale='这条跨文件输入依赖直接控制目标 SQL 注入的连接配置。',
                           evidence=[dict(path='helper.php',start_line=2,end_line=5)],
                           chain=[dict(kind=k,evidence=dict(path='helper.php',start_line=2,end_line=5)) for k in ('input','sink')])
    assert poc_in_focus(run,helper,known_ids=['sqli-main'])
    helper['focus']['chain'] = []
    assert not poc_in_focus(run,helper,known_ids=['sqli-main'])


def test_peer_judgment_commits_through_the_real_store_without_automatic_merging(hosted):
    from audit.review_policy import COMPARISON_POLICY
    store, repo, run = hosted
    task = {**run['task_spec'], 'comparison_policy': COMPARISON_POLICY}
    store._write('UPDATE runs SET task_spec=? WHERE id=?',(json.dumps(task),run['id']))
    for number in (1, 2):
        finding = add_claim(store,run,number,ledger=f'ledger-{number}')
        store._write('UPDATE findings SET primary_location=? WHERE id=?',
                     (json.dumps(dict(path='public/index.php',line=4)),finding['id']))
    batch = store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    assert len(batch['items']) == 2
    first, second = batch['items']
    decisions = [dict(item_id=i['item_id'],revision=i['revision'],decision='accept',
                      rationale='参数流、执行位置和攻击前提均有实际源码支持。',
                      distinct_from=[other['item_id']],comparison_assessments=[dict(item_id=other['item_id'],
                        relation='same_root',rationale='两条记录对应同一输入路径、相同查询操作与相同访问前提。')])
                 for i,other in ((first,second),(second,first))]
    with pytest.raises(ValueError,match='same_root'):
        store.validate_review_decisions(run['id'],batch,decisions)
    assert len(store.list_findings(run['id'])) == 2
    assert not store._row("SELECT 1 FROM audit_review_items WHERE run_id=? AND phase='final'",(run['id'],))
    decisions[0]['distinct_from'] = []
    decisions[1].update(decision='duplicate',duplicate_of=first['item_id'],distinct_from=[])
    validated = store.validate_review_decisions(run['id'],batch,decisions)
    plan = store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='独立判读同根因后明确提交主结论与重复处置。',
                               review_batch_id=batch['id'],review_decisions=validated)
    records = store.list_findings(run['id'])
    assert len(records) == 2 and sum(r['disposition']=='duplicate' for r in records) == 1
    entries,_ = canonical_groups(store.attach_final_decisions(run['id'],records))
    assert len(entries) == 1 and entries[0]['final_disposition']=='accepted'
    assert entries[0]['final_batch_review']['comparison_policy']==COMPARISON_POLICY


def test_early_comparison_is_not_suppressed_by_different_sink_wording(hosted):
    from audit.capability import POLICY
    store,repo,run = hosted
    task = {**run['task_spec'],'capability_policy':POLICY}
    store._write('UPDATE runs SET task_spec=? WHERE id=?',(json.dumps(task),run['id']))
    for number in (1,2):
        finding = add_claim(store,run,number,ledger=f'ledger-{number}')
        store._write('UPDATE findings SET vulnerability_type=?,primary_location=?,dangerous_operation=? WHERE id=?',
                     ('sqli',json.dumps(dict(path='public/index.php',line=4)),f'自由措辞 {number}：执行外部参数拼接的查询',finding['id']))
    items = store._review_candidates(run['id'],'integration')
    assert {i['item_id'] for i in items} == {'ledger-1','ledger-2'}
    assert len(store.list_findings(run['id']))==2
    assert not any(f['verifications'] for f in store.list_findings(run['id']))


def test_deferred_item_is_eligible_when_a_peer_resolution_changes_its_input(hosted):
    store,repo,run = hosted
    for number in (1,2):
        finding=add_claim(store,run,number,ledger=f'ledger-{number}')
        store._write('UPDATE findings SET vulnerability_type=?,primary_location=? WHERE id=?',
                     ('sqli',json.dumps(dict(path='public/index.php',line=4)),finding['id']))
    batch=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    store.defer_review_batch(run['id'],batch['id'],'先隔离各个比较项',split=True)
    single=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    blocked=single['items'][0]
    peer=blocked['payload']['comparison_candidates'][0]
    store.defer_review_batch(run['id'],single['id'],'对照判读不足，暂留待审')
    own_revision=blocked['revision']
    store._write("UPDATE findings SET disposition='duplicate' WHERE id=?",(peer['finding_id'],))
    # Own claim is unchanged, but its comparison dependency has now been settled.
    resumed=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    assert resumed['items'][0]['item_id']==blocked['item_id']
    assert resumed['items'][0]['revision']==own_revision
    assert resumed['items'][0]['payload']['comparison_candidates']==[]
