import copy
import json
from types import SimpleNamespace

import pytest

from audit.capability import POLICY, freeze_focus
from audit.evidence_yield import EvidenceYield
from audit.navigation import ProjectIndex
from audit.review_store import validate_batch
from audit.risk_coverage import freeze, RiskCoverageMixin
from audit.submission import review_contract, review_example
from audit.schemas import PlannerDecision, PocVerificationResult, PocExperiment
from audit.reuse.autocve.knowledge import route
from tests.test_review_closure import state
from tests.test_goal_tasks import _conclusion_finding


def enable(store, run):
    task = {**run['task_spec'], 'capability_policy': POLICY}
    task['audit_focus'] = freeze_focus(task)
    store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(task), run['id']))
    return store.get_run(run['id'])


def test_self_tagged_relevance_cannot_skip_independent_review(state):
    store, repo, run = state
    run = enable(store, run)
    record = _conclusion_finding(run)
    record.update(focus={'objective_ref': 'objective-main', 'relation': 'relevant', 'rationale': 'worker 自己认为有关联，不能代替独立终审。'})
    store.add_finding(record)
    store.set_workflow_stage(run['id'], 'review')
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    decision = dict(item_id=item['item_id'], revision=item['revision'], decision='accept', rationale='实际源码证明存在可触达的外部输入到危险操作链。')
    with pytest.raises(ValueError, match='须独立提交 focus'):
        store.validate_review_decisions(run['id'], batch, [decision])
    # A valid incidental finding remains accepted and in the ledger, but no goal success.
    decision['focus'] = dict(objective_ref='objective-main', relation='incidental', rationale='本项属于独立旁路风险，未证明其影响本次目标的必要利用链。')
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='独立复核旁路风险', review_batch_id=batch['id'], review_decisions=[decision])
    with pytest.raises(ValueError, match='用户目标'):
        store.finalize_goal(run['id'], 'met', '不能用旁路达成用户目标')
    assert store.get_run(run['id'])['status'] == 'running'
    assert len(store.list_findings(run['id'])) == 1


def test_focus_evidence_revision_and_metadata_survive_freeze_and_delete(state):
    from audit.frozen_reports import materialize
    store, repo, run = state
    run = enable(store, run)
    record = _conclusion_finding(run)
    record.update(retest='以原身份测试正常参数，再用注入参数确认均按参数绑定处理。', capability_policy=POLICY,
                  dataflow=[{'kind':'input','evidence':{'path':'public/index.php','start_line':1,'end_line':2},'explanation':'实际原始源码输入位置'}])
    store.add_finding(record)
    stored = store.list_findings(run['id'])[0]
    assert stored['retest'] == record['retest']
    assert stored['dataflow'] == record['dataflow']
    store.terminate_execution(run['id'], 'inconclusive', {'code':'offline', 'message':'离线验证'}, epoch=run['execution_epoch'])
    facts = materialize(store, repo, run['id'])['facts']
    assert facts['schema_version'] == 'final-review/v2'
    assert facts['canonical_findings'][0]['frozen_claim']['retest'] == record['retest']
    assert facts['run_outcome']['audit_complete'] is False
    assert store.get_final_summary(run['id'])['complete'] is False
    store.cache_delivery_export(run['id'], 'derived-v1', b'frozen derived bytes')
    assert store.delivery_export(run['id'], 'derived-v1') == b'frozen derived bytes'
    store.quiesce_execution(run['id'])
    store._db.execute('PRAGMA foreign_keys=OFF')
    store.delete_run(run['id'])
    assert store.frozen_report(run['id']) is None
    assert store.delivery_export(run['id'], 'derived-v1') is None
    assert not store._rows('SELECT * FROM derived_run_reports WHERE run_id=?', (run['id'],))
    store.cache_delivery_export(run['id'], 'late-render', b'must not resurrect')
    assert not store._rows('SELECT * FROM derived_run_reports WHERE run_id=?', (run['id'],))


def test_risk_set_is_stable_bounded_and_not_a_file_category_product():
    project = {'files': [{'path':'entry.php', 'line_count':500}, {'path':'vendor/db.php', 'line_count':10,'dependency_tree':True}],
               'calls': [{'path':'entry.php','line':450,'name':'query'}, {'path':'entry.php','line':450,'name':'query'},
                         {'path':'vendor/db.php','line':2,'name':'query'}, {'path':'entry.php','line':2,'name':'htmlspecialchars'}]}
    task = {'scenario':'sqli'}
    first = freeze(project, task, 'snapshot')
    assert first == freeze(copy.deepcopy(project), task, 'snapshot')
    assert len(first['items']) == 1
    item = first['items'][0]
    assert item['required'] and item['line'] == 450
    # Reading the file head cannot settle its sink at line 450.
    obligation = {**item, 'evidence_complete':True, 'kind':'risk', 'item_id':item['id'], 'revision':'v1', 'operation_read':False}
    batch = {'phase':'final','items':[obligation]}
    decision = dict(item_id=item['id'], revision='v1', decision='resolve', rationale='文件读过但未核对后方实际敏感操作。', risk_outcome='no_evidence')
    with pytest.raises(ValueError, match='实际读取'):
        validate_batch(batch, [decision])
    decision.update(decision='needs_evidence', risk_outcome='pending')
    validate_batch(batch, [decision])
    project['calls'] = [{'path':'entry.php','line':line,'name':'query'} for line in range(1, 400)]
    bounded = freeze(project, task, 'snapshot')
    assert len(bounded['items']) == 256 and bounded['omitted_required'] == 143


def test_source_relations_are_paged_navigation_without_fabricated_edges():
    index = ProjectIndex.from_map({'files':[{'path':'entry.php'},{'path':'helper.php'}],
                                  'includes':[{'from_path':'entry.php','to_path':'helper.php','line':3}],
                                  'symbols':[{'path':'helper.php','name':'load_file','short_name':'load_file','start_line':8,'end_line':20}],
                                  'calls':[{'path':'entry.php','line':40,'name':'load_file'}]})
    page = json.loads(index.relations({'path':'helper.php','symbol':'load_file','limit':1}))
    assert page['total'] == 2 and page['next_offset'] == 1
    assert page['items'][0]['line'] in {3, 40}
    assert '不证明' in page['notice']
    with pytest.raises(ValueError):
        index.relations({'path':'../outside.php'})


def test_knowledge_routes_general_plus_matching_topics_and_records_why():
    selection = route(languages=['php'], checkpoints=['核查 SQL 注入 sqli'], routing_policy='focused-v1')
    assert {r.id for r in selection.refs} == {'audit-evidence-method', 'php-input-to-sink'}
    assert 'tags:sqli' in next(r.reason for r in selection.refs if r.id == 'php-input-to-sink')
    assert selection.total_bytes <= 6144
    assert [r.id for r in route(languages=['php'], checkpoints=['只阅读布局'], routing_policy='focused-v1').refs] == ['audit-evidence-method']


def test_host_submission_preserves_refs_without_preapproving_or_asserting_reads():
    batch = {'id':'batch1','phase':'final','items':[{'kind':'finding','item_id':'canon','revision':'current-fingerprint',
             'finding_id':'finding1','finding_revision':8,'verification_id':'verification8','requires_verification_review':True}]}
    contract = review_contract(batch)
    assert contract['items'][0]['verification_review_ref'] == {'finding_id':'finding1','revision':8,'verification_id':'verification8'}
    sample = PlannerDecision.model_validate(review_example(batch)).model_dump()
    assert sample['review_decisions'][0]['decision'] == 'needs_evidence'
    assert not sample['review_decisions'][0]['distinct_from'] and not sample['verification_reviews']


def test_evidence_yield_does_not_reward_repeated_reads_or_reset_budgets():
    ledger = SimpleNamespace(lines={('a.php', 1, 'hash'):'line'})
    events = []
    policy = EvidenceYield(ledger, ceiling=9, emit=events.append)
    assert policy.extend(6) == 6
    ledger.lines.update({('b.php', i, 'hash'):'line' for i in range(1,31)})
    assert policy.extend(6) == 8
    assert policy.extend(8) == 8
    ledger.lines.update({('c.php', i, 'hash'):'line' for i in range(1,31)})
    assert policy.extend(8) == 9
    assert policy.extend(9) == 9
    assert len(events) == 2


def test_risk_read_proof_uses_exact_operation_even_without_model_assignment(state):
    from tests.test_goal_tasks import proposal
    store, repo, run = state
    run = enable(store, run)
    project = store.get_project_map(run['id'])
    frozen = freeze(project, {'focus_scope':'all'}, run['snapshot_id'])
    assert frozen['items']
    task_spec = {**run['task_spec'], 'risk_coverage_policy':'bounded-v1', 'risk_obligation_set':frozen}
    store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(task_spec),run['id']))
    operation = frozen['items'][0]
    plan = store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='读取风险操作及其上下文',tasks=[proposal('actual-risk-read')])
    task = store.claim_ready_task(run['id'],'worker')
    store.resolve_task_attempt(task['id'],'worker',outcome='no_evidence',result={'outcome':'no_evidence','summary':'已读实际敏感操作，但独立终审仍需核对。','remaining_work':[]},usage={},
        seen=[{'path':operation['path'],'start_line':operation['line'],'end_line':operation['line']}],terminal_reason='completed')
    item = next(i for i in store.risk_review_candidates(run['id']) if i['item_id'] == operation['id'])
    assert item['operation_read'] is True
    assert item['payload']['tasks'][0]['association'] == 'host_exact_read_match'
    assert store.risk_coverage(run['id'])['complete'] is False  # read proof never auto-settles a risk


def test_non_target_unknown_risk_does_not_create_an_endless_mandatory_final_batch(state):
    store, repo, run = state
    run = enable(store,run)
    frozen = freeze(store.get_project_map(run['id']), {'scenario':'sqli'},run['snapshot_id'])
    # This project's readfile signal is outside the explicitly frozen SQLi family.
    assert frozen['items'] and not any(item['required'] for item in frozen['items'])
    spec = {**run['task_spec'],'scenario':'sqli','risk_coverage_policy':'bounded-v1','risk_obligation_set':frozen}
    store._write('UPDATE runs SET task_spec=? WHERE id=?',(json.dumps(spec),run['id']))
    assert store.risk_review_candidates(run['id']) == []
    assert store.risk_coverage(run['id'])['complete'] is True
    assert store.list_risk_obligations(run['id'])['items'][0]['state'] == 'pending'
