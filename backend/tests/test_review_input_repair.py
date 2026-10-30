"""Offline replay of the real run's final-input failures; never opens the live DB."""
import asyncio
import json

import pytest

from audit import agent
from audit.final_review import claim_snapshot, canonical_groups, comparison_candidates
from audit.review_input import source_input
from audit.review_store import dump, review_terminal_reason
from audit.runtime import AgentPolicy
from tests.code_model import CONFIG, ModelFactory, code
from tests.test_host_queue import hosted, add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401


def decisions(batch, choice='accept'):
    return [dict(item_id=i['item_id'], revision=i['revision'], decision=choice,
                 rationale='逐项比对源码和实际观测，依据完整原文完成终审。') for i in batch['items']]


def confirmation(item):
    return dict(finding_id=item['finding_id'], revision=item['finding_revision'], verification_id=item['verification_id'],
                decision='confirmed', rationale_summary='原始正常和攻击观测形成明确对照。')


def read_all(store, repo, run, batch, item):
    for part in item.get('paged_fields', []):
        offset, text = 0, ''
        while offset is not None:
            page = store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], offset, repository=repo)
            assert len(dump(page).encode()) < 8192
            text += page['text']
            offset = page['next_offset']
        assert len(text) == part['characters']
        json.loads(text)


def test_verification_job_output_is_not_repeated_in_the_batch(hosted):
    store, repo, run = hosted
    finding = add_claim(store, run, 1, verified=True)
    record = store.get_finding(finding['id'])['verifications'][-1]
    value = record['agent']
    value['job_results'] = [{'job_id': 'original-job', 'kind': 'http', 'result': {'body': '输出' * 18000, 'http_status': 403}}]
    store._write('UPDATE verifications SET agent=? WHERE finding_id=?', (json.dumps(value), finding['id']))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    assert not item.get('review_input_omitted')
    observations = item['payload']['verification_observations']
    assert observations['normal_observation'] == record['normal_observation']
    assert observations['attack_evidence'] == value['attack_evidence']
    assert observations['job_summaries'][0]['full_record_sha256']
    assert 'job_results' not in observations
    assert store.get_finding(finding['id'])['verifications'][-1]['agent']['job_results'] == value['job_results']
    store.validate_review_decisions(run['id'], batch, decisions(batch), verification_reviews=[confirmation(item)])


def test_six_source_references_are_all_provided(hosted):
    store, repo, run = hosted
    finding = add_claim(store, run, 1)
    refs = [{'path': 'public/index.php', 'start_line': 1, 'end_line': 4}] * 6
    store._write('UPDATE findings SET evidence=? WHERE id=?', (json.dumps(refs), finding['id']))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    assert batch['items'][0]['evidence_complete']
    assert len(batch['items'][0]['source_excerpts']) == 6
    store.validate_review_decisions(run['id'], batch, decisions(batch))


def test_long_source_reference_uses_real_contiguous_windows():
    calls = []
    class Repo:
        def read_source(self, snapshot, path, start, end):
            calls.append((start, end))
            return dict(snapshot_id=snapshot, path=path, start_line=start, end_line=end, truncated=False,
                        lines=[{'number': i, 'text': '源代码'} for i in range(start, end + 1)])
    item = source_input({'payload': {'evidence': [{'snapshot_id': 'snap', 'path': 'a.php', 'range': {'start': 1, 'end': 450}}]}}, Repo())
    assert item['evidence_complete'] and calls == [(1, 200), (201, 400), (401, 450)]


def test_paged_input_requires_host_receipts_and_keeps_fact_revision(hosted):
    store, repo, run = hosted
    add_claim(store, run, 1, verified=True)
    store._write('UPDATE verifications SET attack_observation=?', ('真实观测' * 5000,))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    assert item['paged_fields'] and len(dump(batch['items']).encode()) < 32768
    item['read_ranges'] = {part['field']: [[0, part['characters']]] for part in item['paged_fields']}
    with pytest.raises(ValueError, match='完整正常|完整审查'):
        store.validate_review_decisions(run['id'], batch, decisions(batch), verification_reviews=[confirmation(item)])
    read_all(store, repo, run, batch, item)
    stored = store.active_review_batch(run['id'])
    assert stored['input_hash'] == batch['input_hash'] and stored['items'][0]['revision'] == item['revision']
    assert not stored['items'][0]['review_input_omitted']
    store.validate_review_decisions(run['id'], batch, decisions(batch), verification_reviews=[confirmation(item)])
    store._write("UPDATE findings SET summary='新版本事实' WHERE run_id=?", (run['id'],))
    with pytest.raises(ValueError, match='版本'):
        part = item['paged_fields'][0]
        store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], repository=repo)
    with pytest.raises(ValueError, match='变化'):
        store.validate_review_decisions(run['id'], batch, decisions(batch))


def test_explicit_type_precedes_task_category_and_comparisons_are_conservative():
    finding = dict(id='f1', category='task_goal:v2', vulnerability_type='sqli', primary_location={'path': 'index.php', 'line': 4})
    assert claim_snapshot(finding)['vulnerability_type'] == 'sqli'
    assert claim_snapshot({**finding, 'vulnerability_type': None, 'category': 'sqli'})['vulnerability_type'] == 'sqli'
    assert claim_snapshot({**finding, 'vulnerability_type': 'other'})['vulnerability_type'] == 'other'
    assert claim_snapshot({**finding, 'vulnerability_type': 'unknown', 'category': 'sqli'})['vulnerability_type'] == 'unknown'
    records = [{**finding, 'id': 'f1', 'project_finding_id': 'ledger-1', 'validation_state': 'candidate',
                'finding_kind': 'vulnerability', 'dangerous_operation': 'query', 'preconditions': ['普通身份']},
               {**finding, 'id': 'f2', 'project_finding_id': 'ledger-2', 'validation_state': 'candidate',
                'finding_kind': 'vulnerability', 'dangerous_operation': 'different query', 'preconditions': ['管理员']},
               {**finding, 'id': 'f3', 'project_finding_id': 'ledger-3', 'validation_state': 'candidate',
                'finding_kind': 'vulnerability', 'vulnerability_type': 'csrf'}]
    entries, _ = canonical_groups(records)
    peers = comparison_candidates(entries)
    assert len(entries) == 3 and peers['ledger-1'][0]['item_id'] == 'ledger-2'
    assert 'ledger-3' not in peers


def test_same_anchor_acceptance_requires_an_explicit_comparison(hosted):
    store, repo, run = hosted
    for number in (1, 2):
        finding = add_claim(store, run, number, ledger=f'ledger-{number}')
        store._write('UPDATE findings SET primary_location=? WHERE id=?',
                     (json.dumps({'path': 'public/index.php', 'line': 4}), finding['id']))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    values = decisions(batch)
    with pytest.raises(ValueError, match='comparison_candidates') as refused:
        store.validate_review_decisions(run['id'], batch, values)
    # The refusal must say which item_ids the accept still has to adjudicate: a run
    # submitted the same empty-distinct_from accept twice until the round failed.
    for item in batch['items']:
        assert item['item_id'] in str(refused.value)
    assert 'distinct_from' in str(refused.value)
    # Both items' requirements belong in one refusal.  Naming one per correction made
    # a two-item batch alternate between them until the publish allowance ran out.
    assert str(refused.value).count('写入 item_id=') == 2
    for value in values:
        value['distinct_from'] = [i['item_id'] for i in batch['items'] if i['item_id'] != value['item_id']]
        value['rationale'] = '两处危险操作的调用目标和攻击前身份不同，分别保留；评分或验证状态不作为判重依据。'
    assert store.validate_review_decisions(run['id'], batch, values)
    values[1].update(decision='duplicate', duplicate_of=values[0]['item_id'])
    values[0]['distinct_from'] = []
    assert store.validate_review_decisions(run['id'], batch, values)
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='逐项完成对照与判重。',
                               review_batch_id=batch['id'], review_decisions=values)
    records = store.list_findings(run['id'])
    assert len(records) == 2 and sum(r['disposition'] == 'duplicate' for r in records) == 1
    entries, _ = canonical_groups(store.attach_final_decisions(run['id'], records))
    assert len(entries) == 1 and entries[0]['final_batch_review']['input_policy'] == 'paged-facts-v2'


def test_distinct_comparisons_are_preserved_in_frozen_reports(hosted):
    from copy import deepcopy
    from audit.frozen_reports import materialize
    from audit.report_quality import evaluate
    store, repo, run = hosted
    for number in (1, 2):
        finding = add_claim(store, run, number, ledger=f'ledger-{number}')
        store._write('UPDATE findings SET primary_location=?,dangerous_operation=?,preconditions=? WHERE id=?',
                     (json.dumps({'path': 'public/index.php', 'line': 4}), f'不同查询目标 query_{number}',
                      json.dumps(['普通会员' if number == 1 else '管理员']), finding['id']))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    values = decisions(batch)
    for value in values:
        value['distinct_from'] = [i['item_id'] for i in batch['items'] if i['item_id'] != value['item_id']]
        value['rationale'] = '已核对两处不同的危险操作和攻击前身份，分别保留其根因。'
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='明确区分对照候选根因。',
                               review_batch_id=batch['id'], review_decisions=values)
    store.terminate_execution(run['id'], 'inconclusive', {'code': 'offline'}, epoch=run['execution_epoch'])
    report = materialize(store, repo, run['id'])
    facts = report['facts']
    assert facts['appendix']['comparison_pairs'][0]['status'] == 'distinct'
    assert not any(e['merge_suggestions'] for e in facts['canonical_findings'])
    assert '已明确区分根因' in report['markdown']
    changed = deepcopy(facts)
    for entry in changed['canonical_findings']:
        entry['final_batch_review']['distinct_from'] = []
    result = evaluate(changed, report['markdown'])
    assert any('comparison_candidates_adjudicated' in check for check in result['failed_checks'])


def test_terminal_diagnosis_is_not_an_earlier_transition_message():
    reason = review_terminal_reason([{'final_disposition': 'pending'}] * 5, [], {'basis': '进入终审'})
    assert reason['code'] == 'final_review_needs_evidence' and '5' in reason['message'] and '进入终审' not in reason['message']
    assert review_terminal_reason([], [[{}, {}]])['code'] == 'final_review_incomplete'


def test_a_coverage_stop_keeps_its_own_diagnosis():
    """A run stopped on unread source must not report a generic partial audit."""
    reason = review_terminal_reason([], [], {'code': 'coverage_incomplete', 'basis': '覆盖复核未完成：预算或无进展上限已到'})
    assert reason['code'] == 'coverage_incomplete' and '覆盖复核' in reason['message']
    assert review_terminal_reason([], [], None)['code'] == 'audit_partial'


def test_planner_can_retrieve_paged_input_and_publish_in_one_loop(hosted, monkeypatch):
    store, repo, run = hosted
    add_claim(store, run, 1)
    store._write('UPDATE findings SET summary=?', ('根因依据明确。' * 1800,))
    store.set_workflow_stage(run['id'], 'review')
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    assert item.get('paged_fields')
    request = dict(goal_state='continue', basis_summary='读取完整字段后逐项终审。', review_batch_id=batch['id'], review_decisions=decisions(batch))
    read_code = f"""
import json
for part in {item['paged_fields']!r}:
    offset = 0
    while offset is not None:
        page = json.loads(read_review_input({item['item_id']!r}, part['field'], offset))
        print(page['text'])
        offset = page['next_offset']
"""
    factory = ModelFactory([code(read_code), code(f'final_answer({request!r})')])
    monkeypatch.setattr(agent, 'build_code_model', factory)
    def context():
        return {**store.list_planner_context(run['id'], project_map=store.get_project_map(run['id'])),
                'review_batch': store.active_review_batch(run['id'])}
    events = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=store.get_project_map(run['id']), run_context=context(), context_reader=context,
        task=run['task_spec'], round_no=1, config=CONFIG, budgets={'responses': 3, 'tools': 100, 'seconds': 10},
        policy=AgentPolicy(request_seconds=.5), repository=repo, snapshot_id=run['snapshot_id'],
        allowed_paths=set(run['scope']), pins=store, run_id=run['id'], on_event=events.append))
    assert result['decision'], result
    assert result['usage']['requests'] <= 3
    assert any(e.get('tool') == 'read_review_input' and e['kind'] == 'tool_result' for e in events)
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    value = result['decision']
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary=value['basis_summary'],
                               review_batch_id=value['review_batch_id'], review_decisions=value['review_decisions'])
    assert store.active_review_batch(run['id']) is None


def test_read_receipts_cannot_cross_a_pause_or_fill_unread_gaps(hosted):
    store, repo, run = hosted
    add_claim(store, run, 1)
    store._write('UPDATE findings SET summary=?', ('长字段原文。' * 2000,))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    part = item['paged_fields'][0]
    store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], 0, repository=repo)
    for offset in range(2048, part['characters'], 1024):
        store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], offset, repository=repo)
    with pytest.raises(ValueError, match='完整审查'):
        store.validate_review_decisions(run['id'], batch, decisions(batch))
    store._write("UPDATE runs SET status='paused' WHERE id=?", (run['id'],))
    with pytest.raises(ValueError, match='失效'):
        store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], 1024, repository=repo)


def test_reading_and_fallback_publication_share_three_responses(hosted, monkeypatch):
    store, repo, run = hosted
    add_claim(store, run, 1)
    store._write('UPDATE findings SET summary=?', ('长字段原文。' * 2000,))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    factory = ModelFactory([code("print('尚未提交合法终审')")] * 3)
    monkeypatch.setattr(agent, 'build_code_model', factory)
    context = {**store.list_planner_context(run['id'], project_map=store.get_project_map(run['id'])), 'review_batch': batch}
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=store.get_project_map(run['id']), run_context=context,
        task=run['task_spec'], round_no=1, config=CONFIG, budgets={'responses': 12, 'tools': 100, 'seconds': 10},
        policy=AgentPolicy(request_seconds=.5), repository=repo, snapshot_id=run['snapshot_id'],
        allowed_paths=set(run['scope']), pins=store, run_id=run['id']))
    assert result['decision'] is None and result['usage']['requests'] == 3
    assert len(factory.phases) == 3
    assert store.active_review_batch(run['id'])['status'] == 'pending'
