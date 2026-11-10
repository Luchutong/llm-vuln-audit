"""A real unresolved frontier must be assigned and read, never auto-dismissed."""
import copy
import json

import pytest

from audit.continuations import risk_input
from audit.completion_recovery import grant_paused_time
from audit.risk_coverage import operation_facts
from audit.schemas import ContinueRunRequest
from tests.test_host_queue import hosted, completed_task_with_direction, add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_review_closure_repair import risk_batch
from tests.test_run_continuations import finish, request


def test_close_mode_requires_explicit_audit_and_existing_exhaustive_policy(hosted):
    with pytest.raises(ValueError, match='源码审计'):
        ContinueRunRequest(request_id='invalid-close', mode='review', close_unresolved=True)
    store, _, run = hosted
    add_claim(store, run, 1)
    finish(store, run)
    with pytest.raises(ValueError, match='全量审计'):
        store.create_continuation(run['id'], request(mode='audit', close_unresolved=True))
    assert len(store.list_runs()) == 1


def test_seeds_each_open_identity_keeps_candidate_anchor_and_parent_frozen(hosted):
    store, repo, run, _, _, _ = risk_batch(hosted)
    direction = completed_task_with_direction(store, run)
    task = next(t for t in store.list_tasks(run['id']) if t['task_key'] == 'entry')
    result = task['result']
    # Mixed real/missing filenames must be investigated without deleting either.
    result['host_directions'][0].update(text='public/index.php 和 absent.php 的实际权限边界',
                                        unknown_paths=['absent.php'])
    candidate = dict(id='pending-order', status='pending', hypothesis='读取另一个实际入口验证尚未决的输入候选',
                     primary_location=dict(path='src/files.php', line=4))
    result['candidate_journal'] = [candidate]
    store._write('UPDATE planner_tasks SET result=? WHERE id=?', (json.dumps(result), task['id']))
    original = store._audit_direction_records(run['id'])
    finish(store, run)
    frozen = store.frozen_report(run['id'])['input_json']
    child = store.create_continuation(run['id'], request(mode='audit', close_unresolved=True))
    manifest = child['task_spec']['continuation']['closure_manifest']
    assigned = [d for item in manifest for d in item['direction_ids']]
    expected = {d['id'] for d in original.values() if d['state'] in {'pending', 'assigned'}}
    assert set(assigned) == expected and len(assigned) == len(expected)
    new_records = store._audit_direction_records(child['id'])
    assert all(new_records[d]['state'] == 'assigned' for d in expected)
    assert new_records[direction['id']]['unknown_paths'] == ['absent.php']
    copied = next(t for t in store.list_tasks(child['id']) if t['task_key'] == 'entry')
    assert copied['result']['candidate_journal'] == [candidate]
    assert copied['attempts'] == task['attempts']
    assert copied['max_attempts'] == copied['attempts'] + 1
    assert copied['dependencies'] == task['dependencies']
    assert any(r['path'] == candidate['primary_location']['path'] for r in copied['context_spec']['source_refs'])
    files = {f['path'] for f in store.get_project_map(child['id'])['files']}
    for item in manifest:
        assert 0 < len(item['source_paths']) <= 16
        assert set(item['source_paths']) <= files
        assert len(item['direction_ids']) <= 12
    assert store.frozen_report(run['id'])['input_json'] == frozen
    assert child['agent_policy']['worker_explore_responses'] == 1
    assert child['agent_policy']['worker_yield_max_responses'] == 1


def test_operation_fact_revision_ignores_redundant_reads_but_tracks_actual_changes():
    base = dict(obligation=dict(path='src/file.php', line=3), evidence=[dict(path='src/file.php')],
                findings=[dict(finding_id='claim', revision=1, verification_status='unverified')],
                tasks=[dict(task_key='reader', association='host_exact_read_match', state='completed', summary='原始源码读取')])
    repeated = copy.deepcopy(base)
    repeated['tasks'].append(dict(task_key='another-reader', association='host_exact_read_match', state='running'))
    assert operation_facts(base, True) == operation_facts(repeated, True)
    assert risk_input(base, operation_read=True) == risk_input(repeated, operation_read=True)
    assert risk_input(base) != risk_input(repeated)  # historical policy stays exact
    for part in ('obligation', 'evidence', 'findings', 'read', 'assigned'):
        changed = copy.deepcopy(base)
        read = True
        if part == 'obligation': changed['obligation']['line'] = 4
        elif part == 'evidence': changed['evidence'][0]['path'] = 'src/other.php'
        elif part == 'findings': changed['findings'][0]['verification_status'] = 'rejected'
        elif part == 'read': read = False
        else: changed['tasks'][0]['association'] = 'explicit_assignment'
        assert risk_input(base, operation_read=True) != risk_input(changed, operation_read=read)


def test_unchanged_risk_review_carries_and_duplicate_source_read_does_not_reopen(hosted):
    store, repo, run, batch, decisions, _ = risk_batch(hosted)
    risk = next(i for i in batch['items'] if i['kind'] == 'risk')
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='原始操作与发现引用支持当前风险结论。',
                              review_batch_id=batch['id'], review_decisions=decisions)
    old = copy.deepcopy(next(d for d in decisions if d['item_id'] == risk['item_id']))
    old.update(revision='obsolete-revision', risk_outcome='not_applicable')
    store._write('INSERT INTO audit_review_items VALUES(?,?,?,?,?,?)',
                 (run['id'], 'final', risk['item_id'], old['revision'], batch['id'], json.dumps(old)))
    assert next(i for i in store.risk_coverage(run['id'])['items'] if i['id'] == risk['item_id'])['state'] == 'supported'
    finish(store, run)
    child = store.create_continuation(run['id'], request(mode='audit', close_unresolved=True))
    before = next(i for i in store.risk_review_candidates(child['id']) if i['item_id'] == risk['item_id'])
    review = store._row('SELECT revision FROM audit_review_items WHERE run_id=? AND item_id=?', (child['id'], risk['item_id']))
    assert review and review['revision'] == before['revision']
    # A duplicate exact read changes navigation history, not this immutable operation.
    task = store.list_tasks(child['id'])[0]
    old = store.list_task_attempts(task['id'])[0]
    columns = dict(store._row('SELECT * FROM planner_task_attempts WHERE id=?', (old['id'],)))
    columns.pop('id')
    columns['attempt'] = int(columns['attempt']) + 1
    store._write('INSERT INTO planner_task_attempts ('+','.join(columns)+') VALUES ('+','.join('?' for _ in columns)+')', tuple(columns.values()))
    after = next(i for i in store.risk_review_candidates(child['id']) if i['item_id'] == risk['item_id'])
    assert before['revision'] == after['revision']
    assert not any(i['item_id'] == risk['item_id'] for b in store.review_batches_pending(child['id'], 'final', repo) for i in b)
    finding = store.list_findings(child['id'])[0]
    store._write("UPDATE findings SET title='实际主张已经变更，必须重新终审' WHERE id=?", (finding['id'],))
    assert any(i['item_id'] == risk['item_id'] for b in store.review_batches_pending(child['id'], 'final', repo) for i in b)
    assert next(i for i in store.risk_coverage(child['id'])['items'] if i['id'] == risk['item_id'])['state'] == 'pending'


def test_closure_reservation_only_repartitions_existing_cap(hosted):
    store, repo, run, _, _, _ = risk_batch(hosted)
    finish(store, run)
    child = store.create_continuation(run['id'], request(mode='audit', close_unresolved=True,
        run_limits=dict(responses=56, tools=3951, seconds=1010)))
    store.claim_next_run()
    workflow = store.refresh_review_reserve(child['id'], repo, additional_workers=2)
    reserve = workflow['review_reserve']
    batches = reserve['estimated_batches']
    assert reserve['responses'] == batches + min(6, 2*batches) + 4
    assert sum(workflow['limits'].values()) == 56
    assert store.execution_summary(child['id'])['run_usage']['responses'] == 0
    assert store.execution_summary(child['id'])['run_limits']['seconds'] == 1010
    assert not store._rows('SELECT * FROM audit_review_allowances WHERE run_id=?', (child['id'],))


def test_time_grant_restores_only_unspent_transfer_and_is_idempotent(hosted):
    store, _, run, _, _, _ = risk_batch(hosted)
    finish(store, run)
    child = store.create_continuation(run['id'], request(mode='audit', close_unresolved=True,
        run_limits=dict(responses=56, tools=3951, seconds=1010)))
    store.claim_next_run()
    with pytest.raises(ValueError, match='暂停检查点'):
        grant_paused_time(store, child['id'], 1800, 'grant-one')
    store.request_pause(child['id'])
    store.quiesce_execution(child['id'])
    state = store._row('SELECT workflow FROM run_execution_state WHERE run_id=?', (child['id'],))
    workflow = json.loads(state['workflow'])
    workflow.update(stage='poc', limits=dict(discovery=5, poc=28, review=23),
                    used=dict(discovery=5, poc=2, review=0), transferred=10,
                    discovery_stop=dict(code='poc_window_reserved'))
    store._write('UPDATE run_execution_state SET workflow=?,responses_used=7,tools_used=11 WHERE run_id=?',
                 (json.dumps(workflow), child['id']))
    before = store.execution_summary(child['id'])['run_usage']
    grant = grant_paused_time(store, child['id'], 1800, 'grant-one')
    assert grant['after'] == dict(responses=56, tools=3951, seconds=2810)
    assert grant['returned_source_responses'] == 10 and grant['stage'] == 'discovery'
    assert store.workflow_state(child['id'])['limits'] == dict(discovery=15, poc=18, review=23)
    assert store.execution_summary(child['id'])['run_usage'] == before
    assert grant_paused_time(store, child['id'], 1800, 'grant-one') == grant
    with pytest.raises(ValueError, match='不能改变额度'):
        grant_paused_time(store, child['id'], 3600, 'grant-one')
    assert len(store._rows("SELECT id FROM events WHERE run_id=? AND kind='completion_time_granted'", (child['id'],))) == 1
