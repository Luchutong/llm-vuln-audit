"""Bounded queue replay with real SQLite, source receipts and immutable claims."""
import copy
import json
import asyncio
from types import SimpleNamespace

import pytest

from audit import investigation
from audit.agent import _worker_publication_schema
from audit.role_policy import validate_assessment, validate_planner_actions
from audit.schemas import GoalAssessment
from audit.submission import review_contract
from tests.test_audit_directions import commit
from tests.test_goal_tasks import proposal, _conclusion_finding
from tests.test_worker_evidence_roles import (  # noqa: F401
    owned, exhaustive, hosted, state, PATH, REF, SEEN, TASK, LINES, candidate, finding, disproof,
)

BOUNDED = {**TASK, 'investigation_policy': investigation.POLICY}


@pytest.fixture
def bounded(owned):
    store, repo, run = owned
    store._write('UPDATE runs SET task_spec=? WHERE id=?',
        (json.dumps({**run['task_spec'], 'investigation_policy': investigation.POLICY}), run['id']))
    return store, repo, store.get_run(run['id'])


def claim(**changes):
    return {**finding(), 'vulnerability_type': 'sqli', 'title': '输入进入查询', **changes}


def publish(fixture, result, *, outcome='achieved', seen=SEEN, progress=None):
    store, _, run = fixture
    task = store.claim_ready_task(run['id'], 'worker')
    assert task
    return store.resolve_task_attempt(task['id'], 'worker', outcome=outcome, result=result,
        usage={}, seen=seen, terminal_reason='completed', progress=progress)


@pytest.mark.parametrize('max_attempts', [2, 8])
def test_rephrasing_the_same_root_cannot_buy_investigation_quota(bounded, max_attempts):
    store, _, run = bounded
    commit(store, run, tasks=[proposal('repeat-wallet')])
    store._write('UPDATE planner_tasks SET max_attempts=? WHERE run_id=?', (max_attempts, run['id']))
    raw = []
    for index in range(3):
        result = dict(findings=[claim(title=f'输入进入查询的改写 {index}')], candidate_updates=[candidate()])
        raw.append(copy.deepcopy(result['findings']))
        task = publish(bounded, result, progress={'new_conclusion_keys': [f'forged-novelty-{index}']})
        assert task['result']['host_progress']['new_conclusions'] == (1 if index == 0 else 0)
        assert task['result']['host_progress']['stalled_passes'] == index
    assert task['state'] == 'blocked'
    assert task['result']['investigation_pause']['code'] == 'no_investigation_progress'
    assert [a['result']['findings'] for a in store.list_task_attempts(task['id'])] == raw
    assert store.worker_candidate_gaps(run['id'])  # Pausing is never a negative verdict.
    assert any(e['kind'] == 'worker_investigation_paused' for e in store.list_events(run['id']))


def test_external_dependency_pauses_after_saving_other_findings(bounded):
    store, _, run = bounded
    commit(store, run, tasks=[proposal('runtime-dependent')])
    task = publish(bounded, dict(findings=[claim()], candidate_updates=[candidate(blocked_on='runtime')]))
    assert task['state'] == 'blocked' and task['attempts'] == 1
    assert task['result']['findings'] == [claim()]
    assert task['result']['candidate_journal'][0]['status'] == 'pending'
    assert task['result']['investigation_pause']['code'] == 'candidate_external_dependency'
    assert not store.audit_direction_summary(run['id'])['complete']
    with pytest.raises(ValueError, match='pending'):
        commit(store, run, updates=[dict(task_key=task['task_key'], action='cancel', rationale_summary='暂时没有运行配置也不能抹去未决风险。')])
    commit(store, run, tasks=[proposal('runtime-dependent')], updates=[dict(
        task_key='runtime-dependent', action='reopen', rationale_summary='已请求真实运行配置，重新读取前保留原候选。')])
    reopened = store.claim_ready_task(run['id'], 'worker')
    assert reopened['result']['candidate_journal'][0]['blocked_on'] == 'runtime'


@pytest.mark.parametrize('changes', [dict(status='supported', finding_index=0, missing_context=[]), dict(missing_context=[]), dict(next_step='')])
def test_external_block_requires_a_pending_candidate_and_a_concrete_handoff(changes):
    update = candidate(blocked_on='runtime')
    update.update(changes)
    with pytest.raises(ValueError, match='blocked_on'):
        validate_assessment(BOUNDED, dict(findings=[claim()], candidate_updates=[update]), SEEN, LINES)


def test_new_reads_roots_or_candidate_settlement_reset_only_the_stall_counter():
    previous = dict(host_progress=dict(stalled_passes=1, failed_attempts=1), candidate_journal=[candidate()])
    for result, seen in [
        (dict(findings=[claim(primary_location=dict(path=PATH, line=3))]), SEEN),
        (dict(findings=[claim()]), [*SEEN, dict(path='src/auth.php', start_line=2, end_line=2)]),
        (dict(candidate_journal=[candidate('excluded', disproof=disproof())]), SEEN),
    ]:
        progress = investigation.progress(previous, {**result, 'outcome': 'continue'}, seen, SEEN, [claim()])
        assert progress['productive'] and progress['stalled_passes'] == 0
        assert progress['failed_attempts'] == 1  # Retry budgets are not replenished.
    failed = investigation.progress(previous, dict(outcome='continue', error='invalid JSON'), SEEN, SEEN, [])
    assert failed['stalled_passes'] == 1  # Invalid output uses its own failure budget.


def observation(**changes):
    return dict(kind='security_boundary', title='需要核对的边界', summary='当前操作的实际前提需要进一步取证。',
                evidence=PATH+':1-4', follow_up=True, **changes)


def test_owned_observation_is_not_an_extra_lead_and_pending_remains_a_gap(bounded):
    store, _, run = bounded
    commit(store, run, tasks=[proposal('candidate-owner')])
    task = publish(bounded, dict(candidate_updates=[candidate()], observations=[observation(candidate_id='query-path')]), outcome='continue')
    assert store.list_audit_directions(run['id'])['items'] == []
    assert len(store.worker_candidate_gaps(run['id'])) == 1
    assert task['result']['observations'][0]['candidate_id'] == 'query-path'


def test_unlinked_risk_still_creates_a_lead(bounded):
    store, _, run = bounded
    commit(store, run, tasks=[proposal('new-boundary')])
    publish(bounded, dict(observations=[observation()]), outcome='continue')
    leads = store.list_audit_directions(run['id'])['items']
    assert len(leads) == 1 and leads[0]['source_kind'] == 'observation'
    assert store.list_findings(run['id']) == []


def test_positive_owned_observation_is_not_mistaken_for_a_negative_proof():
    item = observation(finding_index=0)
    item['follow_up'] = False
    validate_assessment(BOUNDED, dict(findings=[claim()], observations=[item]), SEEN, LINES)
    with pytest.raises(ValueError, match='disproof'):
        validate_assessment(TASK, dict(findings=[claim()], observations=[item]), SEEN, LINES)


@pytest.mark.parametrize('owner', [dict(candidate_id='missing'), dict(finding_index=1), dict(finding_id='foreign'),
    dict(candidate_id='query-path', finding_index=0)])
def test_fake_or_ambiguous_observation_owners_are_rejected(owner):
    with pytest.raises(ValueError, match='observations'):
        validate_assessment(BOUNDED, dict(findings=[claim()], candidate_updates=[candidate()], observations=[observation(**owner)]), SEEN, LINES)


def test_owner_must_match_the_actual_read_root_and_current_valid_finding(bounded):
    store, _, run = bounded
    raw = {**_conclusion_finding(run), 'primary_location': dict(path=PATH, line=4)}
    store.add_finding(raw)
    item = observation(finding_id=raw['id'])
    result = dict(observations=[item])
    validate_assessment(BOUNDED, result, SEEN, LINES, known_findings=store.list_findings(run['id']))
    item['evidence'] = PATH+':1-2'
    with pytest.raises(ValueError, match='覆盖所关联根因'):
        validate_assessment(BOUNDED, result, SEEN, LINES, known_findings=store.list_findings(run['id']))
    item['evidence'] = PATH+':1-4'
    store.set_finding_verification_state(raw['id'], 'rejected', 'rejected')
    with pytest.raises(ValueError, match='实际有效'):
        validate_assessment(BOUNDED, result, SEEN, LINES, known_findings=store.list_findings(run['id']))


def test_direction_context_contains_actual_references_without_preselecting_a_verdict(bounded):
    store, _, run = bounded
    commit(store, run, tasks=[proposal('direction-origin')])
    publish(bounded, dict(findings=[claim()], remaining_work=[PATH+':4 具体输入路径需要独立核对。']))
    direction, = store.list_audit_directions(run['id'])['items']
    commit(store, run, tasks=[{**proposal('direction-check'), 'direction_ids': [direction['id']]}])
    publish(bounded, dict(findings=[claim()], direction_results=[dict(direction_id=direction['id'],
        outcome='supported', rationale='已读源码证明该方向与本次输入进入查询的路径一致。')]))
    store.add_finding({**_conclusion_finding(run), 'primary_location': dict(path=PATH, line=4)})
    store.add_finding({**_conclusion_finding(run, 'rejected'), 'verification_status': 'rejected'})
    item = next(i for i in store._review_candidates(run['id'], 'integration') if i['kind'] == 'direction')
    context = item['payload']['resolution_context']
    assert context['worker_results'][0]['outcome'] == 'supported'
    assert [f['id'] for f in context['eligible_findings']] == ['finding-1']
    assert 'decision' not in context
    contract = review_contract(dict(id='batch', phase='integration', items=[item]))
    assert contract['items'][0]['direction_resolution'] == context
    with pytest.raises(ValueError, match='supported.*finding_ids'):
        commit(store, run, directions=[dict(direction_id=direction['id'], action='resolve', task_key='direction-check',
            rationale_summary='需引用真实已落库的对应发现才能结算。')])
    commit(store, run, directions=[dict(direction_id=direction['id'], action='resolve', task_key='direction-check',
        finding_ids=['finding-1'], rationale_summary='独立核对了本方向输入与实际查询操作对应的发现。')])
    assert store.audit_direction_summary(run['id'])['complete']


def test_required_direction_triage_fails_before_model_publication():
    with pytest.raises(ValueError, match='必做方向不能 triage'):
        validate_planner_actions(BOUNDED, direction_updates=[dict(direction_id='direction', action='triage', triage_outcome='covered')],
            directions={'direction': dict(requirement='required')})


def test_new_schema_exposes_checkpoint_and_observation_examples_without_changing_old_policy():
    bounded = _worker_publication_schema(2, task=BOUNDED)
    assert bounded['x-host-investigation-contract']['version'] == investigation.POLICY
    example = bounded['x-host-investigation-contract']['examples'][0]
    GoalAssessment.model_validate(dict(outcome='continue', summary='保存未决候选等待运行配置。', reasoning='源码无法提供运行前提。',
        next_focus='取得实际运行事务配置后核对并发操作。',
        candidate_updates=example['candidate_updates'], observations=example['observations']))
    assert 'x-host-investigation-contract' not in _worker_publication_schema(2, task=TASK)
    old = _worker_publication_schema(2, task=TASK)
    assert 'candidate_id' not in old['$defs']['TaskObservation']['properties']
    assert 'blocked_on' not in old['$defs']['WorkerCandidateUpdate']['properties']


@pytest.mark.parametrize('policy,role,expected', [(None, None, 'bounded-v1'), ('legacy', None, 'legacy'),
    (None, 'legacy', 'legacy'), ('bounded-v1', 'worker-evidence-v1', 'bounded-v1')])
def test_api_freezes_new_policy_without_overwriting_explicit_legacy(bounded, policy, role, expected):
    from audit.app import create_run
    from audit.config import ModelConfig, PocSettings
    from audit.events import EventBus
    from audit.schemas import CreateRunRequest
    store, repo, run = bounded
    services = SimpleNamespace(repository=repo, store=store, bus=EventBus(store),
        settings=SimpleNamespace(model=ModelConfig(model='offline'), poc=PocSettings()),
        worker=SimpleNamespace(notify=lambda: None))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(services=services)))
    task = {**run['task_spec'], 'role_policy': role, 'investigation_policy': policy}
    created = asyncio.run(create_run(request, CreateRunRequest(snapshot_id=run['snapshot_id'], task=task)))
    assert created['task_spec']['investigation_policy'] == expected
    assert store.get_run(run['id'])['task_spec']['investigation_policy'] == investigation.POLICY


@pytest.mark.parametrize('phase', ['task_execute', 'task_publish'])
def test_real_worker_publication_recovers_a_fake_observation_owner(monkeypatch, phase):
    from audit import agent
    from audit.runtime import AgentPolicy
    from tests.code_model import ModelFactory, final_answer
    from tests.test_worker_strategies import Repository, UNIT, CONFIG, assessment
    raw = assessment(dataflow=[dict(kind=kind, evidence=dict(path='src/a.php', start_line=3, end_line=3),
        explanation='实际读取的请求进入输出操作。') for kind in ['input', 'sink']])
    raw['observations'] = [dict(kind='data_flow', title='本次发现的传播补充', summary='此处补充已发布发现，不声称排除其他风险。',
        evidence='src/a.php:3-3', follow_up=False, finding_id='fabricated')]
    corrected = copy.deepcopy(raw)
    corrected['observations'][0].pop('finding_id')
    corrected['observations'][0]['finding_index'] = 0
    factory = ModelFactory({phase: [final_answer(raw), final_answer(corrected)]})
    monkeypatch.setattr(agent, 'build_code_model', factory)
    events = []
    result = asyncio.run(agent.pursue_task_work(repository=Repository(), snapshot_id='snapshot', snapshot_name='example.zip',
        unit=UNIT, task={**BOUNDED, 'objective': '检查真实请求进入响应的路径。', 'require_poc': False}, attempt=1,
        config=CONFIG, budgets=dict(responses=5, tools=0, seconds=5),
        policy=AgentPolicy(request_seconds=1, worker_explore_responses=0 if phase == 'task_publish' else 2), on_event=events.append))
    assert result['outcome'] == 'achieved', result
    assert result['usage']['requests'] == 2
    assert result['result']['observations'][0]['finding_index'] == 0
    assert 'x-host-investigation-contract' in factory.prompts[0]
    assert any(e['kind'] == 'investigation_contract_bound' for e in events)
