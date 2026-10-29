"""Replay the first real batch-review failure; no providers or target actions."""
import asyncio
import copy
import json
from types import SimpleNamespace

import pytest

from audit import agent, worker as worker_module
from audit.review_store import validate_batch
from tests.code_model import ModelFactory
from tests.test_goal_tasks import _conclusion_finding, make_worker
from tests.test_planner_publication_recovery import _plan
from tests.test_review_closure import state


def two_claims(store, run):
    for name in ('a', 'b'):
        store.add_finding({**_conclusion_finding(run, 'finding-' + name), 'unit_id':'unit-' + name})
        store._write('UPDATE findings SET project_finding_id=? WHERE id=?',
                     ('ledger-' + name, 'finding-' + name))


def decisions(batch, choice='retain'):
    return [dict(item_id=item['item_id'], revision=item['revision'], decision=choice,
                 rationale='已对照当前输入证据与根因进行逐项处置。') for item in batch['items']]


@pytest.mark.parametrize('phase', ['integration', 'final'])
def test_current_finding_alias_is_normalized_before_publication_and_commit(state, phase):
    store, repo, run = state
    two_claims(store, run)
    batch = store.prepare_review_batch(run['id'], phase, run['execution_epoch'], repo)
    supplied = decisions(batch, 'accept' if phase == 'final' else 'retain')
    supplied[1].update(decision='duplicate', duplicate_of='finding-a')
    normalized = store.validate_review_decisions(run['id'], batch, supplied)
    assert supplied[1]['duplicate_of'] == 'finding-a'
    assert normalized[1]['duplicate_of'] == 'ledger-a'
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='重复项并入当前主结论',
                               review_batch_id=batch['id'], review_decisions=supplied)
    duplicate = store.get_finding('finding-b')
    assert duplicate['disposition'] == 'duplicate'
    assert duplicate['derived_from_finding_id'] == 'finding-a'
    assert len(store.list_findings(run['id'])) == 2  # History is retained.
    saved = store.list_review_batches(run['id'])[-1]
    assert saved['status'] == 'completed' and saved['decisions'][1]['duplicate_of'] == 'ledger-a'
    assert store.prepare_review_batch(run['id'], phase, run['execution_epoch'], repo) is None


@pytest.mark.parametrize('target', ['unknown', 'foreign-finding', 'finding-b', 'ledger-b'])
def test_invalid_duplicate_target_is_rejected_before_any_mutation(state, target):
    store, repo, run = state
    two_claims(store, run)
    batch = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'], repo)
    supplied = decisions(batch)
    supplied[1].update(decision='duplicate', duplicate_of=target)
    with pytest.raises(ValueError, match='duplicate_of'):
        store.validate_review_decisions(run['id'], batch, supplied)
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    with pytest.raises(ValueError, match='duplicate_of'):
        store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='拒绝未知或自引用的主结论',
                                   review_batch_id=batch['id'], review_decisions=supplied)
    assert not store._rows('SELECT * FROM audit_review_items')
    assert store.active_review_batch(run['id'])['status'] == 'pending'
    assert all(item['disposition'] == 'open' for item in store.list_findings(run['id']))


@pytest.mark.parametrize('target_action', ['duplicate', 'withdraw'])
def test_duplicate_cycles_and_disappearing_primary_claims_are_rejected(state, target_action):
    store, repo, run = state
    two_claims(store, run)
    batch = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'], repo)
    supplied = decisions(batch)
    supplied[0].update(decision=target_action, duplicate_of='ledger-b' if target_action == 'duplicate' else None)
    supplied[1].update(decision='duplicate', duplicate_of='ledger-a')
    with pytest.raises(ValueError, match='保留一条当前主结论'):
        validate_batch(batch, supplied)


def test_real_json_publication_corrects_unknown_reference_then_normalizes_finding_id(state, monkeypatch):
    store, repo, run = state
    two_claims(store, run)
    batch = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'], repo)
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    payload = dict(goal_state='continue', basis_summary='逐项结算本次已领取的冻结候选批次。', tasks=[],
                   review_batch_id=batch['id'], review_decisions=decisions(batch))
    payload['review_decisions'][1].update(decision='duplicate', duplicate_of='unknown')
    corrected = copy.deepcopy(payload)
    corrected['review_decisions'][1]['duplicate_of'] = 'finding-a'
    factory = ModelFactory({'planner_publish':[json.dumps(payload), json.dumps(corrected)]})
    monkeypatch.setattr(agent, 'build_code_model', factory)
    frontier = SimpleNamespace(store=store, repository=repo, run=run, project_map=store.get_project_map(run['id']), plan=plan)
    events = []
    outcome = asyncio.run(_plan(frontier, events))
    assert outcome['terminal_reason'] == 'completed', outcome
    assert outcome['usage']['requests'] == 2
    assert outcome['decision']['review_decisions'][1]['duplicate_of'] == 'ledger-a'
    assert any(event['kind'] == 'agent_output_rejected' for event in events)
    assessment = next(event for event in events if event['kind'] == 'planner_assessment')
    assert assessment['review_batch_id'] == batch['id']
    assert assessment['review_decisions'][1]['duplicate_of'] == 'ledger-a'
    assert factory.phases == ['planner_publish', 'planner_publish']


def test_duplicate_can_refer_to_a_current_primary_claim_reviewed_in_an_earlier_batch(state):
    from tests.test_review_closure import commit
    store, repo, run = state
    store.add_finding(_conclusion_finding(run, 'finding-a'))
    store._write("UPDATE findings SET project_finding_id='ledger-a' WHERE id='finding-a'")
    first = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'], repo)
    commit(store, run, first)
    store.add_finding({**_conclusion_finding(run, 'finding-b'), 'unit_id':'unit-b'})
    store._write("UPDATE findings SET project_finding_id='ledger-b' WHERE id='finding-b'")
    batch = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'], repo)
    assert [item['item_id'] for item in batch['items']] == ['ledger-b']
    supplied = decisions(batch)
    supplied[0].update(decision='duplicate', duplicate_of='finding-a')
    assert store.validate_review_decisions(run['id'], batch, supplied)[0]['duplicate_of'] == 'ledger-a'
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='跨批次重复项保留原始历史。',
                               review_batch_id=batch['id'], review_decisions=supplied)
    assert store.get_finding('finding-b')['derived_from_finding_id'] == 'finding-a'


def test_commit_rejection_is_bounded_and_still_produces_a_partial_report(state, monkeypatch):
    from audit.execution_state import CURRENT_EXECUTION
    store, repo, run = state
    two_claims(store, run)
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context']['review_batch']
        supplied = decisions(batch, 'needs_evidence')
        if batch['phase'] == 'integration':
            supplied[0].update(decision='duplicate', duplicate_of='unknown')
        return {'decision':dict(goal_state='continue', basis_summary='模拟发布与落库之间的状态变化。',
                               review_batch_id=batch['id'], review_decisions=supplied),
                'usage':{'requests':1}, 'terminal_reason':'completed'}
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    asyncio.run(make_worker(store, repo)._execute(run))
    assert store.get_run(run['id'])['status'] == 'inconclusive'
    plans = store.list_plans(run['id'])
    assert sum(plan['status'] == 'failed' for plan in plans) == 2
    assert all(plan['status'] != 'planning' for plan in plans)
    assert store.execution_summary(run['id'])['run_usage']['responses'] == 3
    frozen = store.frozen_report(run['id'])
    assert frozen['facts']['counts']['pending'] == 2
    assert frozen['facts']['quality_result']['publishability'] == 'releasable_partial'


def test_unexpected_body_failure_closes_draft_and_renders_frozen_facts(state, monkeypatch):
    store, repo, run = state
    worker = make_worker(store, repo)
    async def broken_body(_):
        store.add_finding(_conclusion_finding(run))
        store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
        raise ValueError('offline-fault-after-finding')
    monkeypatch.setattr(worker, '_execute_body', broken_body)
    with pytest.raises(ValueError, match='offline-fault-after-finding'):
        asyncio.run(worker._execute(run))
    assert store.get_run(run['id'])['status'] == 'failed'
    assert store.list_plans(run['id'])[0]['status'] == 'failed'
    frozen = store.frozen_report(run['id'])
    assert frozen['facts']['counts']['pending'] == 1
    assert frozen['markdown'] and frozen['zip_blob'] and frozen['json_export']
