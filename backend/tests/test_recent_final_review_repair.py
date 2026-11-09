"""Replay November's peer-publication failures, including continuation ownership."""
import asyncio
import copy
import json

import pytest

from audit import agent, worker as worker_module
from audit import review_store
from audit.execution_state import CURRENT_EXECUTION
from audit.final_review import canonical_groups
from audit.frozen_reports import materialize
from audit.review_policy import COMPARISON_POLICY, validate_peer_assessments
from audit.review_store import dump
from audit.runtime import AgentPolicy
from audit.schemas import PlannerDecision
from audit.submission import review_contract, review_schema
from tests.code_model import CONFIG, ModelFactory
from tests.test_goal_tasks import make_worker
from tests.test_host_queue import hosted, add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_review_input_repair import confirmation, read_all
from tests.test_run_continuations import decisions, finish, request
from tests.test_poc_store import record


def peer_claims(store, run, count=4):
    task = {**run['task_spec'], 'comparison_policy': COMPARISON_POLICY}
    store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(task), run['id']))
    for number in range(count):
        finding = add_claim(store, run, number, ledger=f'ledger-{number}', verified=number > 0)
        store._write('UPDATE findings SET primary_location=?,summary=? WHERE id=?',
            (json.dumps(dict(path='public/index.php', line=4)),
             '已读取参数进入查询并直接执行，无参数化防护；这是同一操作的不同表述。' * 90, finding['id']))
    return store.get_run(run['id'])


def adjudicate(batch):
    primary = batch['items'][-1]
    values = decisions(batch)
    for item, value in zip(batch['items'], values):
        if item['item_id'] != primary['item_id']:
            value.update(decision='duplicate', duplicate_of=primary['item_id'],
                comparison_assessments=[dict(item_id=primary['item_id'], relation='same_root',
                    rationale='两项引用同一输入、同一拼接查询操作且攻击前提一致，属于同一根因的重复表述。')])
    return values


def test_peer_rejection_names_every_item_and_missing_pair_without_guessing_a_relation():
    current = {key: {'payload': {'comparison_candidates': [{'item_id': other}]}}
               for key, other in [('first', 'second'), ('second', 'first')]}
    values = [dict(item_id=key, decision='accept', distinct_from=[other])
              for key, other in [('first', 'second'), ('second', 'first')]]
    with pytest.raises(ValueError) as error:
        validate_peer_assessments(values, current)
    assert 'review_decisions[first].comparison_assessments[second]' in str(error.value)
    assert 'review_decisions[second].comparison_assessments[first]' in str(error.value)
    assert 'same_root' in str(error.value) and '不能为接受捏造' in str(error.value)
    assert all('comparison_assessments' not in value for value in values)


def test_bounded_peer_component_can_retain_one_primary_in_one_transaction(hosted):
    store, repo, run = hosted
    run = peer_claims(store, run)
    groups = store.review_batches_pending(run['id'], 'final', repo)
    assert len(groups) == 1 and len(groups[0]) == 4
    assert 49152 < len(dump(groups[0]).encode()) <= 131072
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    for item in batch['items']:
        read_all(store, repo, run, batch, item)
    values = adjudicate(batch)
    reviews = [confirmation(i) for i in batch['items'] if i['item_id'] == batch['items'][-1]['item_id']]
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='逐项判读关联候选，保留一条规范主结论。',
        review_batch_id=batch['id'], review_decisions=values, verification_reviews=reviews)
    assert len(canonical_groups(store.list_findings(run['id']))[0]) == 1
    assert not store.review_batches_pending(run['id'], 'final', repo)


def test_paged_derived_related_claims_are_rebuilt_and_checked_against_the_original_hash(hosted, monkeypatch):
    store, repo, run = hosted
    add_claim(store, run, 0)
    corroboration = [dict(item_id='write-path', summary='已保存相邻写入路径的原始事实。' * 1600)]
    monkeypatch.setattr(review_store, 'related_claim_facts', lambda *args, **kwargs: corroboration)
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    part = next(p for p in item['paged_fields'] if p['field'] == 'payload.related_claims')
    text, offset = '', 0
    while offset is not None:
        page = store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], offset, repository=repo)
        text += page['text']
        offset = page['next_offset']
    assert json.loads(text) == corroboration
    assert page['sha256'] == part['sha256'] and page['all_paged_fields_read']
    store.validate_review_decisions(run['id'], batch, decisions(batch))
    # A changed projection cannot silently reuse the old manifest or read receipts.
    monkeypatch.setattr(review_store, 'related_claim_facts', lambda *args, **kwargs: [dict(summary='变动后的相邻事实')])
    with pytest.raises(ValueError, match='原文已变化'):
        store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], repository=repo)


def test_oversized_comparison_components_keep_the_original_packing_limits(hosted):
    store, repo, run = hosted
    run = peer_claims(store, run, 9)
    groups = store.review_batches_pending(run['id'], 'final', repo)
    assert sum(map(len, groups)) == 9
    assert all(len(group) <= 8 and len(dump(group).encode()) <= 49152 for group in groups)


def test_comparison_batch_keeps_headroom_for_a_smaller_frozen_context(hosted):
    store, repo, run = hosted
    run = peer_claims(store, run, 4)
    policy = {**run['agent_policy'], 'history_bytes': 131072}
    store._write('UPDATE runs SET agent_policy=? WHERE id=?', (json.dumps(policy), run['id']))
    groups = store.review_batches_pending(run['id'], 'final', repo)
    assert len(groups) > 1 and all(len(dump(group).encode()) <= 65536 for group in groups)


def test_review_schema_drops_scheduling_but_keeps_real_peer_and_verification_contract(hosted):
    store, repo, run = hosted
    run = peer_claims(store, run, 2)
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    full = PlannerDecision.model_json_schema()
    schema = review_schema(copy.deepcopy(full), batch)
    assert 'PlannerTaskProposal' not in schema['$defs']
    assert 'PeerAssessment' in schema['$defs']
    verification_type = schema['properties']['verification_reviews']['items']['$ref'].rsplit('/', 1)[-1]
    assert verification_type in schema['$defs']
    assert 'tasks' not in schema['properties'] and 'direction_updates' not in schema['properties']
    assert len(dump(schema)) < len(dump(full)) / 2
    contract = review_contract(batch)
    assert len(contract['verification_review_refs']) == 1
    assert contract['verification_review_refs'][0]['finding_id'] == 'claim-001'
    assert all(peer['in_current_batch'] for item in contract['items'] for peer in item['peer_comparison_contract'])


def test_invalid_dynamic_review_explains_exact_refs_and_does_not_upgrade_static_claim(hosted):
    store, repo, run = hosted
    add_claim(store, run, 0)
    add_claim(store, run, 1, verified=True)
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    unverified = next(i for i in batch['items'] if i['verification_status'] != 'verified')
    verified = next(i for i in batch['items'] if i['verification_status'] == 'verified')
    bad = [confirmation(unverified), {**confirmation(verified), 'verification_id': 'stale-verification'}]
    with pytest.raises(ValueError) as error:
        store.validate_review_decisions(run['id'], batch, decisions(batch, 'needs_evidence'), verification_reviews=bad)
    assert '须省略该项 verification_reviews' in str(error.value)
    assert f"verification_id={verified['verification_id']}" in str(error.value)
    assert store.get_finding(unverified['finding_id'])['verification_status'] == 'unverified'
    assert not store._rows('SELECT * FROM verification_reviews WHERE run_id=?', (run['id'],))


def test_real_model_gate_corrects_peer_submission_with_actionable_feedback(hosted, monkeypatch):
    store, repo, run = hosted
    run = peer_claims(store, run, 2)
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    answer = dict(goal_state='continue', basis_summary='依据实际输入、操作与前提完成本批判重。',
        review_batch_id=batch['id'], review_decisions=adjudicate(batch),
        verification_reviews=[confirmation(batch['items'][-1])])
    bad = copy.deepcopy(answer)
    bad['review_decisions'] = decisions(batch)
    for value, item in zip(bad['review_decisions'], batch['items']):
        value['distinct_from'] = [p['item_id'] for p in item['payload']['comparison_candidates']]
    factory = ModelFactory({'planner_publish': [json.dumps(bad), json.dumps(answer)]})
    monkeypatch.setattr(agent, 'build_code_model', factory)
    context = {**store.list_planner_context(run['id'], project_map=store.get_project_map(run['id'])), 'review_batch': batch}
    result = asyncio.run(agent.plan_audit_frontier(project_map=store.get_project_map(run['id']), run_context=context,
        task=run['task_spec'], round_no=1, config=CONFIG, budgets=dict(responses=3, tools=32, seconds=10),
        policy=AgentPolicy(request_seconds=.5), repository=repo, snapshot_id=run['snapshot_id'],
        allowed_paths=set(run['scope']), pins=store, run_id=run['id']))
    assert result['decision'], result
    assert result['usage']['requests'] == 2
    assert '主机生成的项目结构概览' not in factory.prompts[0]
    assert 'comparison_assessments[ledger-' in factory.prompts[-1]
    assert 'relation_note' in factory.prompts[0]


@pytest.mark.parametrize('mode', ['review', 'poc_review'])
def test_continuation_runs_the_same_peer_gate_and_preserves_inherited_verifications(hosted, monkeypatch, mode):
    store, repo, run = hosted
    run = peer_claims(store, run, 2)
    store._write("UPDATE runs SET project_mode='project' WHERE id=?", (run['id'],))
    # The synthetic source review explicitly excludes unrelated fixture paths.
    store.append_event(run['id'], None, 'coverage_review_recorded', {'paths': [
        dict(path=p, action='skip', reason='合成回归只检查既有结论的续跑，不审查该辅助文件。') for p in run['scope']]})
    finish(store, run)
    before = store.frozen_report(run['id'])['input_json']
    child = store.create_continuation(run['id'], request(mode=mode, finding_ids=['claim-000'] if mode == 'poc_review' else []))
    claimed = store.claim_next_run()
    verified_before = {f['id']: copy.deepcopy(f['verifications']) for f in store.list_findings(child['id'])
                       if f['verification_status'] == 'verified'}
    tested, batches = [], []

    async def verify(verifier, run_id, findings, verified_for, **kwargs):
        assert mode == 'poc_review'
        for finding in findings:
            tested.append(finding['id'])
            verification = record(finding, record_id='new-retest-verification')
            verification.update(normal_observation='正常参数仅返回本账号。', attack_observation='攻击参数返回其他账号。')
            store.record_automatic_verification(verification)
            verified_for[finding.get('project_finding_id') or finding['id']] = finding.get('project_revision') or 1
        return dict(processed=len(findings), remaining=0)

    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context']['review_batch']
        batches.append(batch)
        for item in batch['items']:
            read_all(store, repo, claimed, batch, item)
        return dict(decision=dict(goal_state='continue', basis_summary='依据继承及本次新增的真实观测逐项完成终审。',
            review_batch_id=batch['id'], review_decisions=adjudicate(batch),
            verification_reviews=[confirmation(batch['items'][-1])]),
            usage={'requests': 1}, terminal_reason='completed')

    monkeypatch.setattr(worker_module.PocVerifier, 'verify_standing', verify)
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    asyncio.run(make_worker(store, repo)._execute(claimed))
    assert tested == child['task_spec']['continuation']['retest_finding_ids']
    assert len(batches) == 1 and len(batches[0]['items']) == 2
    assert store.get_run(child['id'])['status'] == 'completed'
    assert not store.review_batches_pending(child['id'], 'final', repo)
    assert materialize(store, repo, child['id'])['facts']['counts']['accepted'] == 1
    assert store.frozen_report(run['id'])['input_json'] == before
    for ident, verifications in verified_before.items():
        assert store.get_finding(ident)['verifications'] == verifications
