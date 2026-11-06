"""Real queue transitions and source receipts; no benchmark answers or live models."""
import json

import pytest

from audit.role_policy import POLICY, merge_candidates, validate_assessment, validate_planner_actions
from tests.test_exhaustive_exploration import exhaustive, capture, triage  # noqa: F401
from tests.test_goal_tasks import proposal, _conclusion_finding
from tests.test_audit_directions import commit
from tests.test_host_queue import hosted  # noqa: F401
from tests.test_review_closure import state  # noqa: F401

PATH = 'public/index.php'
REF = dict(path=PATH, start_line=1, end_line=4)
SEEN = [REF]
LINES = {PATH: 4}
TASK = dict(role_policy=POLICY)


def disproof(path=PATH):
    return dict(basis='effective_protection', rationale='仅针对当前输入路径核对了实际存在的参数化与权限约束。',
                evidence=[dict(path=path, start_line=1, end_line=4)])


def candidate(status='pending', **changes):
    return dict(candidate_id='query-path', status=status, hypothesis='请求输入是否进入此处查询仍需完整核对。',
                primary_location=dict(path=PATH, line=4), evidence=[REF],
                missing_context=['需要核对实际查询执行参数。'] if status == 'pending' else [],
                next_step='读取调用者与参数绑定语句。', **changes)


def finding():
    return dict(primary_location=dict(path=PATH, line=4), dataflow=[
        dict(kind='input', evidence=REF, explanation='请求参数进入处理逻辑。'),
        dict(kind='sink', evidence=REF, explanation='查询执行实际使用该参数。')])


@pytest.fixture
def owned(exhaustive):
    store, repo, run = exhaustive
    store._write('UPDATE runs SET task_spec=? WHERE id=?',
                 (json.dumps({**run['task_spec'], 'role_policy': POLICY}), run['id']))
    return store, repo, store.get_run(run['id'])


def lead(owned, text='public/index.php:4 请求进入查询的独立路径仍需要判断。'):
    # A scoped safe observation is independent of the still-open question.
    return capture(owned, text=text, observation=dict(kind='security_boundary', title='已有局部防护',
        summary='当前读取只排除了另一条输入路径的具体风险，不代表全部方向安全。',
        evidence='public/index.php:1-4', follow_up=False, disproof=disproof()))[0]


@pytest.mark.parametrize('reason', [
    '根因已经由既有结论覆盖，不需要再新增结论。',
    'Covered by existing findings; no additional evidence.',
    '没有找到 finding，因此本方向可以结算为无证据。',
])
def test_planner_cannot_close_a_source_lead_without_worker_disproof(owned, reason):
    store, _, run = owned
    item = lead(owned)
    with pytest.raises(ValueError, match='Planner 不得'):
        commit(store, run, directions=[dict(direction_id=item['id'], action='triage',
            triage_outcome='no_evidence', rationale_summary=reason, evidence=[REF])])
    assert store.audit_direction_summary(run['id'])['triage_pending_total'] == 1
    triage(store, run, item, 'investigate')
    assert store.list_audit_directions(run['id'])['items'][0]['requirement'] == 'required'


def test_unread_in_scope_source_remains_a_gap_but_unknown_source_is_a_limitation(owned):
    store, _, run = owned
    item = lead(owned, 'src/auth.php:2 冻结源码中的另一个鉴权入口尚未读取。')
    with pytest.raises(ValueError, match='已知源码不能'):
        triage(store, run, item, 'out_of_scope')
    triage(store, run, item, 'blocked')
    assert not store.audit_direction_summary(run['id'])['complete']
    # A path outside this snapshot cannot be invented merely to make the queue drain.
    others = capture(owned, text='missing-router.php:1 外部模块不在冻结快照内。', key='external-lead',
        observation=dict(kind='security_boundary', title='局部防护已核实',
            summary='只核实当前源码路径，外部模块没有被假装读取。', evidence='public/index.php:1-4',
            follow_up=False, disproof=disproof()))
    other = next(item for item in others if item['text'].startswith('missing-router.php'))
    triage(store, run, other, 'out_of_scope')
    assert not store.audit_direction_summary(run['id'])['complete']


def test_covered_requires_the_actual_root_line_not_just_the_same_file(owned):
    store, _, run = owned
    item = lead(owned)
    store.add_finding({**_conclusion_finding(run), 'vulnerability_type': 'sqli',
                       'primary_location': dict(path=PATH, line=4)})
    ident = store.list_findings(run['id'])[0]['id']
    with pytest.raises(ValueError, match='实际根因行'):
        triage(store, run, item, 'covered', finding_ids=[ident],
               evidence=[dict(path=PATH, start_line=1, end_line=1)])
    triage(store, run, item, 'covered', finding_ids=[ident], evidence=[REF])
    assert store.audit_direction_summary(run['id'])['complete']


def test_scheduler_cannot_retract_or_merge_worker_claims():
    for action in ['retract', 'duplicate']:
        with pytest.raises(ValueError, match='独立审查批次'):
            validate_planner_actions(TASK, [dict(action=action)])
    with pytest.raises(ValueError, match='独立审查批次'):
        validate_planner_actions(TASK, project_updates=[dict(action='retract')])
    validate_planner_actions(TASK, [dict(action='reopen')])
    validate_planner_actions({}, [dict(action='retract')])  # historical contract


def test_full_scope_path_coverage_cannot_bypass_worker_ownership(owned):
    store, _, run = owned
    skip = dict(path=PATH, action='skip', reason='没有读取源码，不能据此跳过第一方文件。')
    for spec in [dict(focus_scope='all'), dict(role_policy=POLICY, focus_scope='targeted')]:
        validate_planner_actions(spec, coverage_updates=[skip])
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    with pytest.raises(ValueError, match='coverage_review skip'):
        store.finish_planner_round(run['id'], plan['id'], goal_state='continue',
            basis_summary='未完成项保留覆盖缺口，不用范围排除宣称读取完成。', coverage_review=[skip])
    assert not any(event['kind'] == 'coverage_review_recorded' for event in store.list_events(run['id']))


def test_worker_cannot_assert_no_evidence_or_close_observations_without_source_proof():
    with pytest.raises(ValueError, match='no_evidence 需要'):
        validate_assessment(TASK, dict(outcome='no_evidence'), SEEN, LINES)
    with pytest.raises(ValueError):
        validate_assessment(TASK, dict(outcome='no_evidence', observations=[dict(follow_up=False)]), SEEN, LINES)
    with pytest.raises(ValueError, match='本次实际读取'):
        validate_assessment(TASK, dict(observations=[dict(follow_up=False, disproof=disproof('unread.php'))]), SEEN, LINES)
    validate_assessment(TASK, dict(outcome='no_evidence', observations=[dict(follow_up=False,
                        disproof=disproof())]), SEEN, LINES)


def test_published_chain_requires_read_input_and_root_sink():
    validate_assessment(TASK, dict(findings=[finding()]), SEEN, LINES)
    raw = finding()
    raw['dataflow'] = raw['dataflow'][:1]
    with pytest.raises(ValueError, match='input→sink'):
        validate_assessment(TASK, dict(findings=[raw]), SEEN, LINES)
    raw = finding()
    raw['dataflow'][1]['evidence'] = dict(path=PATH, start_line=1, end_line=1)
    with pytest.raises(ValueError, match='primary_location'):
        validate_assessment(TASK, dict(findings=[raw]), SEEN, LINES)
    raw['dataflow'][1]['evidence'] = dict(path='unread.php', start_line=4, end_line=4)
    with pytest.raises(ValueError, match='实际读取'):
        validate_assessment(TASK, dict(findings=[raw]), SEEN, LINES)


def test_candidates_cannot_disappear_or_claim_support_without_a_published_finding():
    journal = merge_candidates([], [candidate()], [], [(PATH, 1, 4)], LINES)
    assert merge_candidates(journal, [], [], [], LINES) == journal
    with pytest.raises(ValueError, match='finding_index'):
        merge_candidates(journal, [candidate('supported', finding_index=0)], [], [(PATH, 1, 4)], LINES)
    supported = merge_candidates(journal, [candidate('supported', finding_index=0)], [finding()], [(PATH, 1, 4)], LINES)
    assert supported[0]['status'] == 'supported'
    with pytest.raises(ValueError):
        merge_candidates(journal, [candidate('excluded')], [], [(PATH, 1, 4)], LINES)
    excluded = merge_candidates(journal, [candidate('excluded', disproof=disproof())], [], [(PATH, 1, 4)], LINES)
    assert excluded[0]['status'] == 'excluded'


def test_pending_candidates_prevent_a_negative_terminal_assessment():
    with pytest.raises(ValueError, match='pending'):
        validate_assessment(TASK, dict(outcome='no_evidence', candidate_updates=[candidate()],
            observations=[dict(follow_up=False, disproof=disproof())]), SEEN, LINES)


def test_candidate_journal_survives_real_queue_passes_without_minting_duplicate_directions(owned):
    store, _, run = owned
    commit(store, run, tasks=[proposal('candidate-work')])
    task = store.claim_ready_task(run['id'], 'worker')
    first = store.resolve_task_attempt(task['id'], 'worker', outcome='continue',
        result=dict(summary='保留具体待核实候选，下一次继续读参数绑定。', candidate_updates=[candidate()]),
        usage={}, seen=SEEN, terminal_reason='completed')
    assert first['state'] == 'ready' and first['result']['candidate_journal'][0]['status'] == 'pending'
    assert store.list_audit_directions(run['id'])['items'] == []
    store.claim_ready_task(run['id'], 'worker')
    second = store.resolve_task_attempt(task['id'], 'worker', outcome='continue',
        result=dict(summary='本次没有更新候选；宿主仍保留前次待办。'), usage={}, seen=SEEN, terminal_reason='completed')
    assert second['result']['candidate_journal'] == first['result']['candidate_journal']
    assert second['result']['remaining_work']
    store.claim_ready_task(run['id'], 'worker')
    final = store.resolve_task_attempt(task['id'], 'worker', outcome='no_evidence',
        result=dict(summary='已经针对该候选读取并核对实际防护。',
            candidate_updates=[candidate('excluded', disproof=disproof())]), usage={}, seen=SEEN, terminal_reason='completed')
    assert final['state'] == 'completed'
    assert final['result']['candidate_journal'][0]['status'] == 'excluded'
    assert not final['result']['remaining_work']
    assert len(store.list_task_attempts(task['id'])) == 3


def test_worker_negative_direction_has_an_immutable_attempt_receipt(owned):
    store, _, run = owned
    item = lead(owned)
    commit(store, run, tasks=[{**proposal('recheck-query'), 'direction_ids': [item['id']]}])
    task = store.claim_ready_task(run['id'], 'worker')
    outcome = dict(direction_id=item['id'], outcome='no_evidence',
                   rationale='核对该方向的实际防护并留下本次读取凭据。', disproof=disproof())
    store.resolve_task_attempt(task['id'], 'worker', outcome='no_evidence',
        result=dict(summary='完成当前方向的源码防护判断。', direction_results=[outcome]),
        usage={}, seen=SEEN, terminal_reason='completed')
    commit(store, run, directions=[dict(direction_id=item['id'], action='resolve', task_key='recheck-query',
        rationale_summary='仅引用已领取该方向的worker源码反证，结算相同方向ID。')])
    assert store.audit_direction_summary(run['id'])['complete']


def test_direct_store_submission_cannot_bypass_worker_proof_validation(owned):
    store, _, run = owned
    commit(store, run, tasks=[proposal('invalid-negative')])
    task = store.claim_ready_task(run['id'], 'worker')
    with pytest.raises(ValueError, match='no_evidence 需要'):
        store.resolve_task_attempt(task['id'], 'worker', outcome='no_evidence',
            result=dict(summary='没有任何实际防护证据却声称任务已排除。'), usage={}, seen=SEEN, terminal_reason='completed')
    assert store.get_planner_task(task['id'])['state'] == 'running'
    assert store.list_task_attempts(task['id']) == []


def test_worker_disproof_for_another_file_cannot_settle_the_claimed_direction(owned):
    store, _, run = owned
    item = lead(owned, 'src/auth.php:2 需要单独核对的鉴权边界。')
    commit(store, run, tasks=[{**proposal('wrong-disproof'), 'direction_ids': [item['id']],
                            'source_refs': [dict(path='src/auth.php', start_line=1, end_line=3)]}])
    task = store.claim_ready_task(run['id'], 'worker')
    result = dict(summary='防护证据实际位于另一个文件，不能结清当前方向。', direction_results=[
        dict(direction_id=item['id'], outcome='no_evidence', rationale='引用了另一处已读文件的参数校验，尚未针对本方向。', disproof=disproof())])
    with pytest.raises(ValueError, match='本方向的源码路径'):
        store.resolve_task_attempt(task['id'], 'worker', outcome='no_evidence', result=result,
                                   usage={}, seen=SEEN, terminal_reason='completed')
    assert store.get_planner_task(task['id'])['state'] == 'running'
    assert not store.audit_direction_summary(run['id'])['complete']


def test_new_schema_rejects_role_policy_on_a_legacy_scheduler():
    from audit.schemas import CreateRunRequest
    with pytest.raises(ValueError, match='requires host-queue'):
        CreateRunRequest(snapshot_id='snapshot', task=dict(objective='核对请求与数据库之间的实际可达风险。',
            role_policy=POLICY, orchestration_policy='rounds-v1'))


def test_supported_candidate_cannot_hide_its_own_missing_facts():
    raw = candidate('supported', finding_index=0)
    raw['missing_context'] = ['真正的输入来源仍然未读取。']
    with pytest.raises(ValueError, match='缺关键上下文'):
        merge_candidates([], [raw], [finding()], [(PATH, 1, 4)], LINES)


def test_candidate_id_cannot_silently_move_to_a_different_operation():
    old = merge_candidates([], [candidate()], [], [(PATH, 1, 4)], LINES)
    moved = candidate()
    moved['primary_location']['line'] = 3
    with pytest.raises(ValueError, match='悄悄更换'):
        merge_candidates(old, [moved], [], [(PATH, 1, 4)], LINES)


def test_real_worker_runtime_binds_the_role_and_validates_the_chain(monkeypatch):
    import asyncio
    from audit import agent
    from audit.runtime import AgentPolicy
    from tests.code_model import ModelFactory, final_answer
    from tests.test_worker_strategies import Repository, UNIT, CONFIG, assessment
    payload = assessment()
    payload['findings'][0]['dataflow'] = [dict(kind=kind,
        evidence=dict(path='src/a.php', start_line=3, end_line=3), explanation='该行包含请求参数及直接输出操作。')
        for kind in ['input', 'sink']]
    factory = ModelFactory([final_answer(payload)])
    monkeypatch.setattr(agent, 'build_code_model', factory)
    events = []
    result = asyncio.run(agent.pursue_task_work(repository=Repository(), snapshot_id='snapshot', snapshot_name='sample.zip',
        unit=UNIT, task=dict(objective='沿当前源码输入到输出的路径独立判断风险。',
            success_criteria='发布有实际读取依据的独立漏洞结论。', require_poc=False, role_policy=POLICY),
        attempt=1, config=CONFIG, budgets=dict(responses=5, tools=0, seconds=3),
        policy=AgentPolicy(request_seconds=1), on_event=events.append))
    assert result['outcome'] == 'achieved', result
    assert 'Worker 取证职责' in factory.prompts[0]
    assert any(e['kind'] == 'role_contract_bound' and e['agent_role'] == 'worker' for e in events)


def test_planner_runtime_corrects_an_unsupported_negative_into_investigation(owned, monkeypatch):
    import asyncio
    from audit import agent
    from audit.config import ModelConfig
    from audit.runtime import AgentPolicy
    from tests.code_model import ModelFactory
    store, repo, run = owned
    item = lead(owned)
    def decision(outcome):
        return json.dumps(dict(goal_state='continue', basis_summary='为当前具体源码问题安排取证，保留原始线索。',
            direction_updates=[dict(direction_id=item['id'], action='triage', triage_outcome=outcome,
                rationale_summary='不能以无finding或阶段约束代替原始源码的判断。', evidence=[REF])]), ensure_ascii=False)
    factory = ModelFactory({'planner_publish': [decision('no_evidence'), decision('investigate')]})
    monkeypatch.setattr(agent, 'build_code_model', factory)
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    result = asyncio.run(agent.plan_audit_frontier(project_map=store.get_project_map(run['id']),
        run_context=store.list_planner_context(run['id'], project_map=store.get_project_map(run['id'])),
        task=run['task_spec'], round_no=1, config=ModelConfig(model='offline', api_key='test'),
        budgets=dict(responses=8, tools=0, seconds=5), policy=AgentPolicy(request_seconds=.5),
        repository=repo, snapshot_id=run['snapshot_id'], allowed_paths=set(run['scope']),
        pins=store, run_id=run['id'], plan_id=plan['id']))
    assert result['decision'], result
    assert result['decision']['direction_updates'][0]['triage_outcome'] == 'investigate'
    assert any('Planner 调度职责' in prompt for prompt in factory.prompts)


def test_pending_candidate_cannot_be_cancelled_or_hidden_from_completion(owned):
    store, _, run = owned
    commit(store, run, tasks=[proposal('candidate-frontier')])
    task = store.claim_ready_task(run['id'], 'worker')
    store.resolve_task_attempt(task['id'], 'worker', outcome='continue', result=dict(
        summary='保留有具体操作位置的待核实候选。', candidate_updates=[candidate()]),
        usage={}, seen=SEEN, terminal_reason='completed')
    for action in ['cancel', 'defer']:
        with pytest.raises(ValueError, match='pending 候选'):
            commit(store, run, updates=[dict(task_key='candidate-frontier', action=action,
                rationale_summary='不能通过调度状态变化隐藏尚未完成的取证。')])
    # Even an externally orphaned task cannot turn the candidate into completed coverage.
    store._write("UPDATE planner_tasks SET state='cancelled' WHERE id=?", (task['id'],))
    summary = store.audit_direction_summary(run['id'])
    assert summary['candidate_pending_total'] == summary['unsettled_total'] == 1
    assert not summary['complete']
    with pytest.raises(ValueError, match='宿主未决方向'):
        store.finalize_goal(run['id'], 'met', '尚有任务内候选，不能宣称已完成。')


def test_candidate_context_has_no_host_fields_to_copy_back():
    from audit.role_policy import candidate_context
    journal = [dict(candidate(), source_attempt=2),
               dict(candidate('excluded', disproof=disproof()), candidate_id='other', source_attempt=1)]
    context = candidate_context(journal)
    assert 'source_attempt' not in context['pending'][0]
    assert context['settled'][0]['status'] == 'excluded'
    assert 'disproof' not in context['settled'][0]


def test_scheduler_schema_advertises_only_its_authorized_actions():
    from audit.role_policy import planner_schema
    from audit.schemas import PlannerDecision
    schema = planner_schema(PlannerDecision.model_json_schema(), full_scope=True)
    assert schema['properties']['project_updates']['maxItems'] == 0
    assert schema['properties']['coverage_review']['maxItems'] == 0
    actions = schema['$defs']['PlannerTaskUpdate']['properties']['action']['enum']
    assert 'reopen' in actions and 'retract' not in actions and 'duplicate' not in actions
    choices = schema['$defs']['PlannerDirectionUpdate']['properties']['triage_outcome']['anyOf'][0]['enum']
    assert 'investigate' in choices and 'no_evidence' not in choices
