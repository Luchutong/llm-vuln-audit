"""Host-queue contract replay. Temporary sources/SQLite and simulated models only."""
import asyncio
import json

import pytest

from audit import agent, worker as worker_module
from audit.execution_state import CURRENT_EXECUTION, FULL_RUN_LIMITS, execution_context, execution_role
from audit.final_review import canonical_groups
from audit.frozen_reports import materialize
from audit.runtime import AgentPolicy, StopAudit
from audit.schemas import CreateRunRequest
from audit.workflow import freeze_workflow
from tests.code_model import ModelFactory
from tests.test_goal_tasks import TASK, _conclusion_finding, make_worker, proposal, worker_outcome
from tests.test_poc_store import record
from tests.test_review_closure import state  # noqa: F401 — shared isolated fixture


@pytest.fixture
def hosted(state):
    store, repo, run = state
    task = {**run['task_spec'], 'orchestration_policy': 'host-queue-v1',
            'completion_policy': 'coverage_review', 'stop_on_achieved': False}
    store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(task), run['id']))
    run = store.get_run(run['id'])
    store._write('UPDATE run_execution_state SET limits=?,workflow=? WHERE run_id=?',
                 (json.dumps(FULL_RUN_LIMITS), json.dumps(freeze_workflow(run, FULL_RUN_LIMITS)), run['id']))
    return store, repo, store.get_run(run['id'])


def add_claim(store, run, number, *, ledger=None, verified=False):
    finding = {**_conclusion_finding(run, f'claim-{number:03}'), 'unit_id': f'unit-{number}',
               'title': f'输入参数 {number} 进入查询', 'fingerprint': f'fingerprint-{number}'}
    store.add_finding(finding)
    if ledger is not None:
        store._write('UPDATE findings SET project_finding_id=?,project_revision=? WHERE id=?',
                     (ledger, 1 + number // 23, finding['id']))
    if verified:
        verification = record(store.get_finding(finding['id']), record_id=f'verification-{number}')
        verification.update(normal_observation='普通输入只返回当前账号记录。', attack_observation='攻击输入返回其它账号记录。')
        verification['agent'].update(context_id=f'context-{number}', run_finding_revision=1,
                                     jobs=[f'job-{number}'], normal_evidence=[{'job_id': f'job-{number}', 'channel': 'stdout', 'excerpt': 'normal'}],
                                     attack_evidence=[{'job_id': f'job-{number}', 'channel': 'stdout', 'excerpt': 'attack'}])
        store.record_automatic_verification(verification)
    return store.get_finding(finding['id'])


def submit(store, run, batch, *, invalid=None):
    decisions, reviews = [], []
    for item in batch['items']:
        choice = 'needs_evidence' if item.get('review_input_omitted') or item['kind'] == 'direction' else 'accept'
        decisions.append(dict(item_id=item['item_id'], revision=item['revision'], decision=choice,
                              rationale='依据宿主冻结源码和正常攻击观测逐项完成判读。'))
        if item.get('verification_status') == 'verified' and not item.get('review_input_omitted'):
            reviews.append(dict(finding_id=item['finding_id'], revision=item['finding_revision'],
                                verification_id=item['verification_id'], decision='confirmed',
                                rationale_summary='正常与攻击观测构成对照，并支持当前源码根因。'))
    if invalid:
        invalid(decisions, reviews)
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='统一终审离线回放',
                               review_batch_id=batch['id'], review_decisions=decisions, verification_reviews=reviews)
    return decisions, reviews


def test_mode_defaults_and_explicit_historical_policy_are_frozen():
    full = CreateRunRequest(snapshot_id='snap', task={**TASK, 'completion_policy': 'coverage_review'})
    assert full.run_limits.model_dump() == FULL_RUN_LIMITS
    assert full.task.orchestration_policy == 'host-queue-v1'
    partial = CreateRunRequest(snapshot_id='snap', task={**TASK, 'completion_policy': 'coverage_review'}, run_limits={'responses': 100})
    assert partial.run_limits.model_dump() == {**FULL_RUN_LIMITS, 'responses': 100}
    quick = CreateRunRequest(snapshot_id='snap', task=TASK)
    assert quick.run_limits.model_dump() == {'responses': 256, 'tools': 2048, 'seconds': 1800}
    assert quick.task.orchestration_policy == 'rounds-v1'
    old = CreateRunRequest(snapshot_id='snap', task={**TASK, 'completion_policy': 'coverage_review',
        'orchestration_policy': 'rounds-v1'}, run_limits={'responses': 256, 'tools': 2048, 'seconds': 720})
    assert old.task.orchestration_policy == 'rounds-v1' and old.run_limits.seconds == 720


def test_old_round_cap_does_not_limit_host_queue(hosted):
    store, _, run = hosted
    for _ in range(31):
        plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
        store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='记录调度序号，实际消费仍受全局约束。')
    session = store.get_planner_session(run['id'])
    assert session['current_round'] == 31 and session['max_rounds'] == 24
    assert session['effective_round_limit'] is None and not session['round_limit_applies']


def test_actual_byte_packing_and_reserve_preserve_the_single_ledger(hosted):
    store, repo, run = hosted
    for i in range(37):
        add_claim(store, run, i, verified=True)
        store._write('UPDATE verifications SET normal_observation=? WHERE finding_id=?', ('中英 observation ' * 200, f'claim-{i:03}'))
    batches = store.review_batches_pending(run['id'], 'final', repo)
    assert sum(map(len, batches)) == 37
    assert len(batches) > 5  # Byte capacity, not merely ceil(37/8).
    assert all(len(json.dumps(batch, ensure_ascii=False).encode()) < 34000 for batch in batches)
    workflow = store.refresh_review_reserve(run['id'], repo, additional_workers=2)
    assert workflow['review_reserve']['responses'] == 3 * len(batches) + 12
    assert workflow['review_reserve']['seconds'] == 60 * (len(batches) + 5)
    assert sum(workflow['limits'].values()) == 512
    assert sum(workflow['used'].values()) == 0
    assert all(workflow['limits'][stage] >= workflow['used'][stage] for stage in workflow['limits'])
    with execution_context(store, run['id'], run['execution_epoch']), execution_role('worker'):
        CURRENT_EXECUTION.get().admit('responses')
    refreshed = store.refresh_review_reserve(run['id'], repo)
    assert sum(refreshed['limits'].values()) == 512
    assert store.execution_summary(run['id'])['run_usage']['responses'] == 1


def test_fixed_quotas_are_not_expanded_and_reserve_only_gates_new_work(hosted):
    store, repo, run = hosted
    task = {**run['task_spec'], 'workflow_limits': {'discovery': 510, 'poc': 0, 'review': 2}}
    run = {**run, 'task_spec': task}
    store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(task), run['id']))
    initial = freeze_workflow(run, FULL_RUN_LIMITS)
    store._write('UPDATE run_execution_state SET workflow=? WHERE run_id=?', (json.dumps(initial), run['id']))
    add_claim(store, run, 1)
    state = store.refresh_review_reserve(run['id'], repo)
    assert state['limits'] == initial['limits'] and not state['review_reserve']['funded']
    assert not state['review_reserve']['upstream_allowed']
    # With the frozen review reserve still available, a new admission is allowed; the
    # reserve gates new work, it is not a second hard deadline for the current stage.
    reserved = state['review_reserved_seconds']
    assert reserved > 0
    store._write('UPDATE run_execution_state SET active_elapsed_ms=? WHERE run_id=?',
                 (int((FULL_RUN_LIMITS['seconds'] - reserved - 50) * 1000), run['id']))
    with execution_context(store, run['id'], run['execution_epoch']), execution_role('worker'):
        CURRENT_EXECUTION.get().admit('responses')
    assert store.execution_summary(run['id'])['run_usage']['responses'] == 1
    # The host queue gets no exemption: once less than the review reserve remains, no
    # new side effect may start, so the reserved final-review window survives.
    store._write('UPDATE run_execution_state SET active_elapsed_ms=? WHERE run_id=?',
                 (int((FULL_RUN_LIMITS['seconds'] - reserved + 10) * 1000), run['id']))
    with execution_context(store, run['id'], run['execution_epoch']), execution_role('worker'):
        with pytest.raises(StopAudit):
            CURRENT_EXECUTION.get().admit('responses')
    assert store.execution_summary(run['id'])['run_usage']['responses'] == 1


def test_29_records_23_entities_six_verifications_have_one_final_pass(hosted):
    store, repo, run = hosted
    for i in range(29):
        add_claim(store, run, i, ledger=f'ledger-{i % 23}', verified=i >= 23)
    assert store.prepare_review_batch(run['id'], 'integration', run['execution_epoch']) is None
    for _ in range(25):
        plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
        store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='回放原先混合回合规模。')
    store.set_workflow_stage(run['id'], 'review')
    before = {item['item_id']: item['revision'] for item in store._review_candidates(run['id'], 'final')}
    while batch := store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo):
        submit(store, run, batch)
    after = {item['item_id']: item['revision'] for item in store._review_candidates(run['id'], 'final')}
    assert before == after  # Review output does not invalidate its own facts.
    assert len(store.list_verification_reviews(run['id'])) == 6
    assert len(store._rows("SELECT * FROM audit_review_items WHERE phase='final'", ())) == 23
    assert not store.unreviewed_verified_findings(run['id'])
    entries, _ = canonical_groups(store.attach_final_decisions(run['id'], store.list_findings(run['id'])))
    assert len(entries) == 23 and all(e['final_batch_review'] for e in entries)
    assert all(e['final_disposition'] == 'accepted' for e in entries)
    store.terminate_execution(run['id'], 'inconclusive', {'code': 'offline', 'message': '离线规模验收'}, epoch=run['execution_epoch'])
    facts = materialize(store, repo, run['id'])['facts']
    assert facts['counts'] == {'raw_records': 29, 'valid_records': 29, 'canonical': 23,
                               'withdrawn': 0, 'accepted': 23, 'pending': 0, 'contested': 0}
    assert facts['provenance']['immutable']


@pytest.mark.parametrize('bad', ['old_revision', 'unknown_verification', 'accept_contested', 'illegal_item', 'late_transaction_error'])
def test_unified_review_rejects_invalid_inputs_atomically(hosted, monkeypatch, bad):
    store, repo, run = hosted
    add_claim(store, run, 1, verified=True)
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    def corrupt(decisions, reviews):
        if bad == 'old_revision': reviews[0]['revision'] += 1
        elif bad == 'unknown_verification': reviews[0]['verification_id'] = 'invented'
        elif bad == 'accept_contested': reviews[0]['decision'] = 'contested'
        elif bad == 'illegal_item': decisions[0]['item_id'] = 'invented'
        else:
            original = store.record_verification_reviews
            def late(*args, **kwargs):
                original(*args, **kwargs)
                raise ValueError('simulated transaction failure after review insert')
            monkeypatch.setattr(store, 'record_verification_reviews', late)
    with pytest.raises(ValueError):
        submit(store, run, batch, invalid=corrupt)
    assert store.list_verification_reviews(run['id']) == []
    assert not store._rows('SELECT * FROM audit_review_items', ())
    assert store.active_review_batch(run['id'])['status'] == 'pending'


def test_truncated_observations_cannot_support_confirmation(hosted):
    store, repo, run = hosted
    add_claim(store, run, 1, verified=True)
    store._write('UPDATE verifications SET attack_observation=?', ('超长真实观测' * 20000,))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    assert batch['items'][0]['review_input_omitted']
    decisions, reviews = submit(store, run, batch)
    assert not reviews and decisions[0]['decision'] == 'needs_evidence'


def completed_task_with_direction(store, run, *, required=False, explicit_result=False):
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='审计单点入口', tasks=[proposal('entry')])
    task = store.claim_ready_task(run['id'], 'offline')
    result = dict(outcome='no_evidence', summary='已核对入口源码，建议未来检查业务前提。', reasoning='读取源码核对了当前分配范围。',
                  remaining_work=['public/index.php 以后可补充业务前提验证'])
    store.resolve_task_attempt(task['id'], 'offline', outcome='no_evidence', result=result, usage={},
                               seen=[{'path': 'public/index.php', 'start_line': 1, 'end_line': 4}], terminal_reason='completed')
    task = store.get_planner_task(task['id'])
    direction = store.list_audit_directions(run['id'])['items'][0]
    if required:
        result = task['result']
        result['host_directions'][0].update(requirement='required', state='assigned', assigned_task_key=task['task_key'])
        if explicit_result:
            result['direction_results'] = [{'direction_id': direction['id'], 'outcome': 'no_evidence', 'rationale': '核对对应方向的数据流与权限检查，未见额外证据。'}]
        store._write('UPDATE planner_tasks SET result=? WHERE id=?', (json.dumps(result), task['id']))
    return direction


def test_worker_advisory_does_not_block_or_require_integration(hosted):
    store, repo, run = hosted
    direction = completed_task_with_direction(store, run)
    assert direction['requirement'] == 'advisory' and not direction['assigned_task_key']
    summary = store.audit_direction_summary(run['id'])
    assert summary['complete'] and summary['unsettled_total'] == 0 and summary['advisory_total'] == 1
    assert store.prepare_review_batch(run['id'], 'integration', run['execution_epoch']) is None
    store.terminate_execution(run['id'], 'inconclusive', {'code': 'offline'}, epoch=run['execution_epoch'])
    facts = materialize(store, repo, run['id'])['facts']
    assert facts['advisory_directions'][0]['id'] == direction['id']
    assert facts['coverage']['directions']['required'] == 0


def test_required_direction_needs_exact_worker_assessment_and_nonblocking_batch(hosted):
    store, repo, run = hosted
    completed_task_with_direction(store, run, required=True)
    batch = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'])
    item = batch['items'][0]
    decisions = [dict(item_id=item['item_id'], revision=item['revision'], decision='resolve', rationale='不能用 completed 或已读路径代替语义判读。')]
    with pytest.raises(ValueError, match='direction_id'):
        store.validate_review_decisions(run['id'], batch, decisions)
    # A pending batch does not prevent unrelated planning, nor does deferral settle it.
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='继续其它可执行方向。', tasks=[proposal('unrelated')])
    assert store.claim_ready_task(run['id'], 'offline')['task_key'] == 'unrelated'
    store.defer_review_batch(run['id'], batch['id'], 'bounded retry exhausted')
    assert store.prepare_review_batch(run['id'], 'integration', run['execution_epoch']) is None
    assert store.audit_direction_summary(run['id'])['unsettled_total'] == 1
    assert any(i['kind'] == 'direction' for group in store.review_batches_pending(run['id'], 'final', repo) for i in group)


def test_no_progress_ignores_logs_names_and_priorities(hosted):
    store, _, run = hosted
    assert not store.host_progress_stalled(run['id'])
    store.append_event(run['id'], None, 'offline_diagnostic', {'counter': 999})
    assert not store.host_progress_stalled(run['id'])
    assert store.host_progress_stalled(run['id'])
    add_claim(store, run, 1)
    assert not store.host_progress_stalled(run['id'])


def test_withdrawn_entity_does_not_resurrect_its_older_source_record(hosted):
    store, repo, run = hosted
    add_claim(store, run, 1, ledger='one-ledger')
    add_claim(store, run, 24, ledger='one-ledger')
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    def withdraw(decisions, reviews):
        decisions[0]['decision'] = 'withdraw'
    submit(store, run, batch, invalid=withdraw)
    assert store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo) is None
    assert len(store.list_findings(run['id'])) == 2  # Source content and history retained.
    assert all(f['disposition'] == 'retracted' for f in store.list_findings(run['id']))


def test_reserve_and_consumption_survive_pause_without_renewing_any_quota(hosted):
    store, repo, run = hosted
    add_claim(store, run, 1)
    before = store.refresh_review_reserve(run['id'], repo, additional_workers=1)
    store.admit_execution(run['id'], run['execution_epoch'], 'responses')
    store.request_pause(run['id'])
    store.quiesce_execution(run['id'])
    assert store.resume_run(run['id'])
    resumed = store.claim_next_run()
    assert resumed['task_spec']['orchestration_policy'] == 'host-queue-v1'
    after = store.workflow_state(run['id'])
    assert after['limits'] == before['limits']
    assert sum(after['used'].values()) == 1
    assert resumed['execution_epoch'] > run['execution_epoch']


def test_concurrent_reserve_updates_and_admissions_share_one_budget(hosted):
    from concurrent.futures import ThreadPoolExecutor
    store, repo, run = hosted
    add_claim(store, run, 1)
    def spend(_):
        state = store.refresh_review_reserve(run['id'], repo, additional_workers=1)
        assert sum(state['limits'].values()) == 512
        store.admit_execution(run['id'], run['execution_epoch'], 'responses')
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(spend, range(12)))
    summary = store.execution_summary(run['id'])
    assert summary['run_usage']['responses'] == 12
    assert sum(summary['workflow']['used'].values()) == 12
    assert sum(summary['workflow']['limits'].values()) == 512


def test_a_worker_naming_two_files_in_prose_does_not_make_a_direction_unassignable(hosted):
    """`files.php/auth.php` names two frozen files, not one missing path.

    A real run's worker wrote `report.php/member_lookup.php`; the host read the
    joined token as one unknown path, kept the direction advisory-only and then
    refused every adoption attempt until the coverage review closed the run.
    """
    store, repo, run = hosted
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='审计单点入口', tasks=[proposal('entry')])
    task = store.claim_ready_task(run['id'], 'offline')
    store.resolve_task_attempt(task['id'], 'offline', outcome='no_evidence', result=dict(
        outcome='no_evidence', summary='已核对入口源码，建议未来检查业务前提。', reasoning='读取源码核对了当前分配范围。',
        remaining_work=['src/files.php 与 src/auth.php 的边界需补读，files.php/auth.php 的调用链一并核对'],
    ), usage={}, seen=[{'path': 'public/index.php', 'start_line': 1, 'end_line': 4}], terminal_reason='completed')
    direction = store.list_audit_directions(run['id'])['items'][0]
    assert direction['requirement'] == 'advisory' and direction['unknown_paths'] == []
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='明确采纳后续方向并分配窄任务。',
                               tasks=[{**proposal('adopt'), 'direction_ids': [direction['id']]}])
    adopted = next(item for item in store.list_audit_directions(run['id'], state='all')['items']
                   if item['id'] == direction['id'])
    assert adopted['requirement'] == 'required' and adopted['assigned_task_key'] == 'adopt'


def test_an_unknown_path_refusal_names_the_names_and_the_allowed_actions(hosted):
    """A refusal the Planner cannot act on closed a real run's discovery stage."""
    store, repo, run = hosted
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='审计单点入口', tasks=[proposal('entry')])
    task = store.claim_ready_task(run['id'], 'offline')
    store.resolve_task_attempt(task['id'], 'offline', outcome='no_evidence', result=dict(
        outcome='no_evidence', summary='已核对入口源码，建议未来检查业务前提。', reasoning='读取源码核对了当前分配范围。',
        remaining_work=['public/index.php 与 missing/helper.php 的调用关系需补读'],
    ), usage={}, seen=[{'path': 'public/index.php', 'start_line': 1, 'end_line': 4}], terminal_reason='completed')
    direction = store.list_audit_directions(run['id'])['items'][0]
    assert direction['unknown_paths'] == ['missing/helper.php']
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    with pytest.raises(ValueError) as refused:
        store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='明确采纳后续方向并分配窄任务。',
                                   tasks=[{**proposal('adopt'), 'direction_ids': [direction['id']]}])
    message = str(refused.value)
    assert direction['id'] in message and 'missing/helper.php' in message
    assert 'skip' in message and 'resolve' in message


def test_adoption_and_explicit_worker_evidence_resolve_required_direction(hosted):
    store, repo, run = hosted
    direction = completed_task_with_direction(store, run)
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='明确采纳后续方向并分配窄任务。',
                               tasks=[{**proposal('adopt'), 'direction_ids': [direction['id']]}])
    assert store.audit_direction_summary(run['id'])['unsettled_total'] == 1
    task = store.claim_ready_task(run['id'], 'offline')
    result = dict(outcome='no_evidence', summary='核对当前入口业务前提，缺少额外漏洞证据。', reasoning='以已读源码逐项核对领取方向。',
                  remaining_work=[], host_directions=[{**direction, 'requirement': 'advisory'}],
                  direction_results=[dict(direction_id=direction['id'], outcome='no_evidence', rationale='已核对该入口身份前提与参数处理，未见额外危险数据流。')])
    store.resolve_task_attempt(task['id'], 'offline', outcome='no_evidence', result=result, usage={},
                               seen=[{'path': 'public/index.php', 'start_line': 1, 'end_line': 4}], terminal_reason='completed')
    assert store.audit_direction_summary(run['id'])['unsettled_total'] == 1  # Worker cannot downgrade or self-settle.
    batch = store.prepare_review_batch(run['id'], 'integration', run['execution_epoch'], repo)
    item = batch['items'][0]
    decisions = [dict(item_id=item['item_id'], revision=item['revision'], decision='resolve', rationale='本方向有同 ID 的源码取证与明确语义结论，可正式结算。')]
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='显式结算必做方向。',
                               review_batch_id=batch['id'], review_decisions=decisions)
    assert store.audit_direction_summary(run['id'])['complete']


@pytest.mark.parametrize('context_probe', [False, True])
def test_planner_initial_publication_has_no_mandatory_exploration(hosted, monkeypatch, context_probe):
    from tests.test_planner_publication_recovery import CONFIG, _decision
    from tests.code_model import code
    store, repo, run = hosted
    context = lambda: store.list_planner_context(run['id'], project_map=store.get_project_map(run['id']))
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    outputs = [json.dumps(_decision('entry'), ensure_ascii=False)]
    if context_probe:
        outputs.insert(0, json.dumps(dict(goal_state='continue', basis_summary='缺少一个入口行的具体上下文。',
                                         missing_context=['public/index.php:1-4 的入口包含关系'], tasks=[])))
    factory = ModelFactory({'planner_publish': outputs,
                            'planner_decision': [code("print(read_source('public/index.php', 1, 4))")]})
    monkeypatch.setattr(agent, 'build_code_model', factory)
    events = []
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=store.get_project_map(run['id']), run_context=context(), context_reader=context,
        task=run['task_spec'], round_no=1, config=CONFIG, budgets={'responses': 8, 'tools': 12, 'seconds': 8},
        policy=AgentPolicy(request_seconds=.5), repository=repo, snapshot_id=run['snapshot_id'],
        allowed_paths=set(run['scope']), pins=store, run_id=run['id'], plan_id=plan['id'], on_event=events.append))
    assert result['decision'], result
    if context_probe:
        assert factory.phases == ['planner_publish', 'planner_decision', 'planner_publish'], factory.phases
        assert any(e['kind'] == 'tool_call' for e in events)
    else:
        assert result['usage']['requests'] == 1
        assert factory.phases == ['planner_publish']
        assert not [e for e in events if e['kind'] == 'tool_call']


def test_coordinator_skips_retain_and_independent_dynamic_review(hosted, monkeypatch):
    store, repo, run = hosted
    calls = []
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context'].get('review_batch')
        if batch:
            calls.append(batch['phase'])
            decision = dict(goal_state='continue', basis_summary='依据冻结源码统一终审。', review_batch_id=batch['id'],
                review_decisions=[dict(item_id=i['item_id'], revision=i['revision'], decision='accept', rationale='源码原文与当前结论相符，静态证据充分。') for i in batch['items']])
        elif not store.list_tasks(run['id']):
            calls.append('planning')
            decision = dict(goal_state='continue', basis_summary='派发具体入口', tasks=[proposal('entry')])
        else:
            calls.append('coverage')
            decision = dict(goal_state='met', basis_summary='当前范围已结算，覆盖限制明确记录。', tasks=[],
                coverage_review=[{'path': path, 'action': 'skip', 'reason': '离线验收只审查入口，依赖模块明确作为未审限制。'}
                                 for path in ('src/auth.php', 'src/files.php')])
        return dict(decision=decision, usage={'requests': 1}, terminal_reason='completed')
    async def source(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        finding = dict(title='外部路径进入文件读取', kind='vulnerability', severity='high', summary='外部路径未经范围约束流入文件读取，可越过预期目录。',
                       vulnerability_type='path_traversal', primary_location={'path': 'public/index.php', 'line': 4},
                       evidence='public/index.php:4-4', dangerous_operation='readfile of user input')
        return worker_outcome('achieved', finding=finding, seen=[{'path': 'public/index.php', 'start_line': 1, 'end_line': 4}])
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    monkeypatch.setattr(worker_module, 'pursue_planner_task', source)
    asyncio.run(make_worker(store, repo)._execute(run))
    final = store.get_run(run['id'])
    assert final['status'] in {'completed', 'inconclusive'}, final.get('error')
    assert calls.count('final') == 1 and 'integration' not in calls, calls
    assert store.frozen_report(run['id'])['facts']['counts']['accepted'] == 1
