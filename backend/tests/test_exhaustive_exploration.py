"""Real host transitions on unrelated source; no benchmark answers or model calls."""
import io
import asyncio
import json
import zipfile

import pytest
from pydantic import ValidationError

from audit.schemas import CreateRunRequest
from audit.source import SourceRepository
from audit.risk_coverage import freeze
from audit.final_review import canonical_groups, comparison_candidates
from audit.review_store import related_claim_facts
from tests.test_host_queue import hosted  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_goal_tasks import proposal, _conclusion_finding
from tests.test_audit_directions import commit


@pytest.fixture
def exhaustive(hosted):
    store, repo, run = hosted
    task = {**run['task_spec'], 'exploration_policy': 'exhaustive-v1', 'focus_scope': 'all'}
    store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(task), run['id']))
    return store, repo, store.get_run(run['id'])


def capture(exhaustive, *, text=None, observation=None, key='source-review'):
    store, _, run = exhaustive
    commit(store, run, tasks=[proposal(key)])
    row = store.claim_ready_task(run['id'], 'worker')
    store.resolve_task_attempt(row['id'], 'worker', outcome='no_evidence', result={
        'summary': '读取实际源码后保存独立调查线索。', 'remaining_work': [text] if text else [],
        'observations': [observation] if observation else [],
    }, usage={}, seen=[dict(path='public/index.php', start_line=1, end_line=4)], terminal_reason='completed')
    return store.list_audit_directions(run['id'])['items']


def triage(store, run, lead, outcome, **extra):
    return commit(store, run, directions=[dict(direction_id=lead['id'], action='triage', triage_outcome=outcome,
        rationale_summary='根据已读原始源码独立判断本方向的风险与现有结论范围。', **extra)])


def test_exhaustive_is_an_explicit_all_scope_host_policy():
    from tests.test_goal_tasks import TASK
    assert CreateRunRequest(snapshot_id='snapshot', task=TASK).task.exploration_policy == 'legacy'
    task = {**TASK, 'exploration_policy': 'exhaustive-v1'}
    with pytest.raises(ValidationError, match='focus_scope'):
        CreateRunRequest(snapshot_id='snapshot', task=task)
    full = CreateRunRequest(snapshot_id='snapshot', task={**task, 'focus_scope': 'all', 'completion_policy': 'coverage_review'})
    assert full.task.orchestration_policy == 'host-queue-v1'


def test_unselected_advisory_cannot_disappear_at_closure(exhaustive):
    store, _, run = exhaustive
    lead, = capture(exhaustive, text='public/index.php:4 请求参数仍有不同授权边界需要检查。')
    summary = store.audit_direction_summary(run['id'])
    assert summary['triage_pending_total'] == summary['unsettled_total'] == 1
    assert summary['unsettled_required_total'] == 0
    with pytest.raises(ValueError, match='宿主未决方向'):
        store.finalize_goal(run['id'], 'met', '文件已经读过，仍不能跳过具体风险方向。')
    with pytest.raises(ValueError, match='triage'):
        commit(store, run, directions=[dict(direction_id=lead['id'], action='skip', rationale_summary='不能凭一句已读过就丢弃该方向。')])
    triage(store, run, lead, 'investigate')
    updated = store.list_audit_directions(run['id'])['items'][0]
    assert updated['requirement'] == 'required' and updated['state'] == 'pending'


def test_observations_are_review_leads_and_never_automatic_findings(exhaustive):
    store, _, run = exhaustive
    lead, = capture(exhaustive, observation=dict(kind='security_boundary', title='局部边界观察',
        summary='该处防护只涉及输入类型，其他安全属性仍需独立判断。', evidence='public/index.php:1-4'))
    assert lead['source_kind'] == 'observation'
    assert store.list_findings(run['id']) == []
    with pytest.raises(ValueError, match='实际读取'):
        triage(store, run, lead, 'no_evidence', evidence=[dict(path='src/files.php', start_line=3, end_line=3)])
    triage(store, run, lead, 'no_evidence', evidence=[dict(path='public/index.php', start_line=1, end_line=4)])
    assert store.audit_direction_summary(run['id'])['complete']
    assert store.list_findings(run['id']) == []


def test_covered_requires_a_real_current_claim_and_reopens_after_revision(exhaustive):
    store, _, run = exhaustive
    lead, = capture(exhaustive, text='public/index.php:4 检查此前是否真的存在该根因结论。')
    evidence = [dict(path='public/index.php', start_line=4, end_line=4)]
    with pytest.raises(ValueError, match='actual current finding_ids'):
        triage(store, run, lead, 'covered', evidence=evidence)
    finding = {**_conclusion_finding(run), 'vulnerability_type': 'sqli',
               'primary_location': dict(path='public/index.php', line=4)}
    store.add_finding(finding)
    triage(store, run, lead, 'covered', evidence=evidence, finding_ids=[finding['id']])
    assert store.audit_direction_summary(run['id'])['complete']
    store._write('UPDATE findings SET revision=revision+1,summary=? WHERE id=?', ('新修订改变了原结论范围，需要重新判断关联。', finding['id']))
    assert store.audit_direction_summary(run['id'])['triage_pending_total'] == 1


def test_unknown_path_and_blocked_triage_keep_honest_limits(exhaustive):
    store, _, run = exhaustive
    lead, = capture(exhaustive, text='missing-router.php:1 外部调用路径在冻结源码中缺失。')
    with pytest.raises(ValueError, match='known frozen source paths'):
        triage(store, run, lead, 'investigate')
    triage(store, run, lead, 'blocked')
    assert not store.audit_direction_summary(run['id'])['complete']
    triage(store, run, lead, 'out_of_scope')
    assert store.audit_direction_summary(run['id'])['complete']
    record = store.list_audit_directions(run['id'], state='all')['items'][0]
    assert record['limitation']


def test_unread_known_lead_is_settled_as_an_explicit_scope_limitation_not_by_invented_evidence(exhaustive):
    """No worker read the named path, so the only honest settlement is out_of_scope."""
    store, _, run = exhaustive
    lead, = capture(exhaustive, text='src/auth.php:2 另一个入口的授权边界仍需核实。')
    assert lead['paths'] == ['src/auth.php'] and not lead.get('review_evidence')
    with pytest.raises(ValueError, match='必须引用'):
        triage(store, run, lead, 'no_evidence')
    with pytest.raises(ValueError, match='从未被 worker 读取'):
        triage(store, run, lead, 'out_of_scope', evidence=[dict(path='src/auth.php', start_line=2, end_line=2)])
    triage(store, run, lead, 'out_of_scope')
    summary = store.audit_direction_summary(run['id'])
    assert summary['complete'] and summary['unsettled_total'] == 0
    record = store.list_audit_directions(run['id'], state='all')['items'][0]
    assert record['state'] == 'skipped' and record['limitation']


def test_source_signals_are_candidates_with_exact_lines_and_no_filename_rules(tmp_path, monkeypatch):
    repo = SourceRepository(tmp_path / 'sources')
    source = '''<?php
$fn = $_GET['call']; $fn($_GET['arg']);
$digest = md5($_POST['secret']);
$details = $error->getTraceAsString();
$identity = $_COOKIE['access'];
if ($_SERVER['HTTP_X_IDENTITY'] === 'yes') { grant_access(); }
db()->prepare('UPDATE profiles SET email=?')->execute([$_POST['email']]);
// md5($unread); $_COOKIE['role'];
$text = 'md5($not_code)';
'''
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        z.writestr('src/unrelated.php', source)
    snap = repo.import_zip(stream.getvalue(), 'source.zip')
    project = repo.build_project_map(snap['id'], include_risk_signals=True)
    signals = {(s['risk'], s['line']) for s in project['risk_signals']}
    assert {('code_execution', 2), ('weak_crypto', 3), ('info_disclosure', 4), ('auth_bypass', 5), ('auth_bypass', 6), ('csrf', 7)} <= signals
    assert not any(line in {8, 9} for _, line in signals)
    old = freeze(project, {'focus_scope': 'all'}, snap['id'])
    new = freeze(project, {'focus_scope': 'all', 'risk_coverage_policy': 'bounded-v2'}, snap['id'])
    assert old['version'] == 'risk-obligations/v1' and new['version'] == 'risk-obligations/v2'
    assert len(new['items']) > len(old['items'])
    assert all(item['state'] == 'pending' for item in new['items'])
    # An old index can be projected in memory; its archived syntax bytes stay intact.
    path = repo._directory(snap['id']) / 'syntax.json'
    syntax = json.loads(path.read_text())
    for file in syntax.values():
        file.pop('risk_signals', None)
    original = path.read_bytes()
    monkeypatch.setattr(repo, 'syntax_index', lambda snapshot_id: syntax)
    assert repo.build_project_map(snap['id'], include_risk_signals=True)['risk_signals'] == project['risk_signals']
    assert path.read_bytes() == original


def test_file_inclusion_capabilities_nominate_a_review_without_changing_types():
    records = []
    for kind in ['lfi', 'rfi']:
        records.append(dict(id=kind, finding_kind='vulnerability', validation_state='candidate',
            vulnerability_type=kind, title='文件包含能力', primary_location=dict(path='src/render.php', line=9),
            evidence=[dict(path='src/render.php', start_line=8, end_line=10)]))
    groups, _ = canonical_groups(records)
    assert not comparison_candidates(groups)
    peers = comparison_candidates(groups, inclusion_family=True)
    assert set(peers) == {'lfi', 'rfi'}
    assert records[0]['vulnerability_type'] == 'lfi'


def test_same_sink_cross_type_claims_are_nominated_for_comparison():
    records = [
        dict(id='trav', finding_kind='vulnerability', validation_state='candidate',
             vulnerability_type='path_traversal', title='模板路径穿越', primary_location=dict(path='src/render.php', line=9),
             evidence=[dict(path='src/render.php', start_line=8, end_line=10)], dangerous_operation='include $view'),
        dict(id='lfi', finding_kind='vulnerability', validation_state='candidate',
             vulnerability_type='lfi', title='模板本地文件包含', primary_location=dict(path='src/render.php', line=9),
             evidence=[dict(path='src/render.php', start_line=8, end_line=10)], dangerous_operation='include $view'),
    ]
    groups, _ = canonical_groups(records)
    peers = comparison_candidates(groups)
    assert set(peers) == {'trav', 'lfi'}
    assert peers['trav'][0]['basis_kind'] == 'same_anchor'
    assert '同一主定位上的不同分类' in peers['trav'][0]['basis']


def test_adjacent_authorization_variants_are_nominated_but_not_merged():
    records = [
        dict(id='auth', finding_kind='vulnerability', validation_state='candidate',
             vulnerability_type='auth_bypass', title='伪造管理员令牌', primary_location=dict(path='src/portal.php', line=3),
             evidence=[dict(path='src/portal.php', start_line=2, end_line=5)], dangerous_operation='if ($payload["role"] !== "admin")'),
        dict(id='idor', finding_kind='vulnerability', validation_state='candidate',
             vulnerability_type='idor', title='结算查询缺少归属限制', primary_location=dict(path='src/portal.php', line=4),
             evidence=[dict(path='src/portal.php', start_line=3, end_line=5)], dangerous_operation='SELECT order_no FROM orders'),
    ]
    groups, _ = canonical_groups(records)
    peers = comparison_candidates(groups)
    assert set(peers) == {'auth', 'idor'}
    assert peers['idor'][0]['basis_kind'] == 'near_authz_variant'


def test_related_claims_expose_a_writable_source_column_without_merging_claims():
    report = {
        'kind': 'finding', 'item_id': 'report',
        'payload': {
            'finding_id': 'report', 'vulnerability_type': 'sqli',
            'title': '报表二次注入', 'summary': '读取 nickname 后再次拼入 SQL。',
            'input_source': 'users.nickname 字段', 'primary_location': dict(path='src/report.php', line=3),
            'dangerous_operation': 'query("... WHERE nickname=\'".$nickname."\'")',
            'evidence': [dict(path='src/report.php', start_line=2, end_line=3)],
        },
        'source_excerpts': [dict(path='src/report.php', start_line=2, end_line=3,
                                 text="$nickname=$q->fetchColumn();$rows=db()->query(\"WHERE nickname='\".$nickname.\"'\")")],
    }
    update = {
        'kind': 'finding', 'item_id': 'update',
        'payload': {
            'finding_id': 'update', 'vulnerability_type': 'mass_assignment',
            'title': '资料批量赋值', 'summary': '账户资料更新接受 role/balance/tier 等字段。',
            'input_source': '已登录用户 POST /account/update.php',
            'primary_location': dict(path='src/update.php', line=6),
            'dangerous_operation': 'UPDATE users SET ... WHERE id=?',
            'evidence': [dict(path='src/update.php', start_line=4, end_line=6)],
        },
        'source_excerpts': [dict(path='src/update.php', start_line=4, end_line=6,
                                 text="$columns=['display_name','email','role','balance','tier','nickname','homepage'];")],
    }
    unrelated = {
        'kind': 'finding', 'item_id': 'ping',
        'payload': {'finding_id': 'ping', 'vulnerability_type': 'command_injection', 'title': '命令注入',
                    'summary': 'host 参数拼入 shell_exec。', 'input_source': '$_GET["host"]',
                    'primary_location': dict(path='src/ping.php', line=2), 'dangerous_operation': 'shell_exec($cmd)',
                    'evidence': [dict(path='src/ping.php', start_line=2, end_line=2)]},
        'source_excerpts': [dict(path='src/ping.php', start_line=2, end_line=2, text='shell_exec("ping -c 1 ".$host);')],
    }
    facts = related_claim_facts(report, [report, update, unrelated])
    assert [fact['item_id'] for fact in facts] == ['update']
    assert facts[0]['shared_tables'] == ['users']
    assert 'nickname' in facts[0]['source_excerpts'][0]['text']
    assert facts[0]['relation'].startswith('同一运行内的相邻结论')


def test_related_claims_read_the_numbered_lines_returned_by_the_source_repository():
    """``read_source`` stores ``lines: [{number,text}]``; copying ``text`` alone yields empty evidence."""
    report = {
        'kind': 'finding', 'item_id': 'report',
        'payload': {
            'finding_id': 'report', 'vulnerability_type': 'sqli',
            'title': '报表二次注入', 'summary': '读取 nickname 后再次拼入 SQL。',
            'input_source': 'users.nickname 字段', 'primary_location': dict(path='src/report.php', line=3),
            'dangerous_operation': "query(\"WHERE nickname='\".$nickname.\"'\")",
            'evidence': [dict(path='src/report.php', start_line=2, end_line=3)],
        },
        'source_excerpts': [dict(path='src/report.php', start_line=2, end_line=3,
                                 lines=[dict(number=2, text='$nickname=$q->fetchColumn();'),
                                        dict(number=3, text="$rows=db()->query(...)")])],
    }
    update = {
        'kind': 'finding', 'item_id': 'update',
        'payload': {
            'finding_id': 'update', 'vulnerability_type': 'mass_assignment',
            'title': '资料批量赋值', 'summary': '账户资料更新接受 nickname 等字段。',
            'input_source': '已登录用户 POST /account/update.php',
            'primary_location': dict(path='src/update.php', line=6),
            'dangerous_operation': 'UPDATE users SET ... WHERE id=?',
            'evidence': [dict(path='src/update.php', start_line=4, end_line=6)],
        },
        'source_excerpts': [dict(path='src/update.php', start_line=4, end_line=6,
                                 lines=[dict(number=4, text="$columns=[...'nickname'...];"),
                                        dict(number=5, text="foreach($_POST as $key=>$value)")])],
    }
    facts = related_claim_facts(report, [report, update])
    assert [fact['item_id'] for fact in facts] == ['update']
    excerpt = facts[0]['source_excerpts'][0]
    assert "nickname" in excerpt['text'] and excerpt['text'].startswith("$columns=")
    assert excerpt['path'] == 'src/update.php'


@pytest.mark.parametrize('role, strategy', [(None, 'worker-exhaustive-v2'), ('legacy', 'worker-exhaustive-v1'),
    ('worker-evidence-v1', 'worker-exhaustive-v2'), ('worker-evidence-v2', 'worker-exhaustive-v2')])
def test_api_freezes_strategy_and_extended_signals_without_running_a_model(tmp_path, monkeypatch, role, strategy):
    from audit.app import Services, create_audit_run
    from audit.config import Settings, ModelConfig
    monkeypatch.setenv('LAB30_SEED', '0')
    service = Services(Settings(data_dir=tmp_path, model=ModelConfig(model='fixture', api_key='test-only')))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        z.writestr('public/new.php', "<?php\n$fn=$_GET['handler'];$fn($_GET['arg']);\n")
    snapshot = service.repository.import_zip(stream.getvalue(), 'source.zip')
    service.store.add_snapshot(snapshot)
    try:
        payload = CreateRunRequest(snapshot_id=snapshot['id'], task=dict(
            objective='审查完整源码中的所有风险并结算独立方向。', completion_policy='coverage_review',
            focus_scope='all', exploration_policy='exhaustive-v1', risk_coverage_policy='bounded-v2', role_policy=role))
        run = asyncio.run(create_audit_run(service, payload))
        assert run['status'] == 'pending'
        assert run['worker_strategy']['id'] == strategy
        assert run['task_spec']['role_policy'] == ('worker-evidence-v2' if role is None else role)
        assert len(run['worker_strategy']['text_sha256']) == 64
        assert any(o['risk'] == 'code_execution' for o in run['task_spec']['risk_obligation_set']['items'])
        assert service.store.execution_summary(run['id'])['run_usage']['responses'] == 0
    finally:
        service.store.close()


def test_lead_overflow_cannot_claim_complete(exhaustive, monkeypatch):
    from audit import exhaustive as policy
    store, _, run = exhaustive
    monkeypatch.setattr(policy, 'MAX_LEADS', 0)
    assert capture(exhaustive, text='public/index.php:4 的具体风险尚未结算。') == []
    summary = store.audit_direction_summary(run['id'])
    assert summary['omitted_leads'] == summary['unsettled_total'] == 1
    assert not summary['complete']


def test_settled_observation_is_not_reopened_as_a_lead(exhaustive):
    """A worker that read the lines and ruled one concrete risk out says so."""
    store, _, run = exhaustive
    observation = dict(kind='security_boundary', title='口令比较核对',
                       summary='注册与登录路径均使用单向散列校验，该具体风险已核实排除。',
                       evidence='public/index.php:1-4', follow_up=False)
    assert capture(exhaustive, observation=observation) == []
    summary = store.audit_direction_summary(run['id'])
    assert summary['triage_pending_total'] == 0 and summary['complete']
    open_lead = capture(exhaustive, key='source-review-2', observation={**observation, 'follow_up': True})
    assert len(open_lead) == 1 and open_lead[0]['source_kind'] == 'observation'
    assert not store.audit_direction_summary(run['id'])['complete']


def test_only_presentation_whitespace_cannot_duplicate_one_observation_lead(exhaustive):
    store, _, run = exhaustive
    observation = dict(kind='source_observation', title='客户端价格来源',
                       summary='提交的价格被直接用于计算订单总额。', evidence='public/index.php:1-4')
    first = capture(exhaustive, observation=observation)
    assert len(first) == 1
    repeated = capture(exhaustive, key='source-review-2', observation={
        **observation, 'title': ' 客户端价格来源 ', 'summary': '提交的价格被直接用于计算订单总额。\t'})
    assert repeated == first
    assert len(store.list_audit_directions(run['id'], state='all')['items']) == 1


def test_observation_triage_may_reuse_its_own_worker_read_citation(exhaustive):
    store, _, run = exhaustive
    lead, = capture(exhaustive, observation=dict(kind='security_boundary', title='会话校验观察',
        summary='该处只证明认证门禁存在，按角色覆盖的边界仍待独立判断。', evidence='public/index.php:1-4'))
    assert lead['review_evidence'] == [dict(path='public/index.php', start_line=1, end_line=4)]
    triage(store, run, lead, 'no_evidence')
    record = store.list_audit_directions(run['id'], state='all')['items'][0]
    assert record['triage']['evidence'] == lead['review_evidence']
    assert store.audit_direction_summary(run['id'])['complete']
    # A lead that was not captured from worker-read spans still needs its own proof.
    followup, = capture(exhaustive, key='source-review-2', text='public/index.php:4 仍有独立方向待判断。')
    with pytest.raises(ValueError, match='实际读取'):
        triage(store, run, followup, 'no_evidence')
    assert not store.audit_direction_summary(run['id'])['complete']


def test_a_direction_owned_by_an_open_task_cannot_be_dispatched_again(exhaustive):
    from audit.agent import _validate_direction_contract
    from audit.schemas import PlannerDecision
    store, _, run = exhaustive
    lead, = capture(exhaustive, text='public/index.php:4 的输入边界仍需独立核对。')
    commit(store, run, tasks=[{**proposal('owner-flow'), 'direction_ids': [lead['id']]}])
    prior = store.list_tasks(run['id'])
    assert next(item for item in prior if item['task_key'] == 'owner-flow')['state'] in {'pending', 'ready'}
    decision = PlannerDecision(goal_state='continue', basis_summary='演示重复派工必须被宿主拒绝。',
                               tasks=[proposal('duplicate-flow')],
                               direction_updates=[dict(direction_id=lead['id'], action='assign',
                                   task_key='duplicate-flow', rationale_summary='把同一线索再交给另一个新任务。')])
    with pytest.raises(Exception, match='重复分派'):
        _validate_direction_contract(decision, workflow_policy='discovery_first',
                                     directions=store.list_audit_directions(run['id'], state='all')['items'],
                                     prior_tasks=prior, findings=[])
    # Reopening the owner is the supported way to move work to another task.
    allowed = PlannerDecision(goal_state='continue', basis_summary='重开原任务后再改派该线索。',
                              tasks=[proposal('duplicate-flow')],
                              updates=[dict(task_key='owner-flow', action='reopen',
                                            rationale_summary='原任务范围过宽，改为由新任务处理该入口线索。')],
                              direction_updates=[dict(direction_id=lead['id'], action='assign',
                                  task_key='duplicate-flow', rationale_summary='重开原任务后把线索交给新任务。')])
    _validate_direction_contract(allowed, workflow_policy='discovery_first',
                                 directions=store.list_audit_directions(run['id'], state='all')['items'],
                                 prior_tasks=prior, findings=[])


def test_adopting_a_lead_requires_reading_the_source_it_names(exhaustive):
    """A task that adopts a lead has the lead's source appended to its reading window."""
    from audit.agent import _validate_planner_decision
    from audit.runtime import AgentPolicy
    from audit.schemas import PlannerDecision
    store, _, run = exhaustive
    project_map = store.get_project_map(run['id'])
    assert 'src/auth.php' in {item['path'] for item in project_map['files']}
    directions = [dict(id='lead-cookie', state='pending', requirement='required',
                       paths=['src/auth.php'], text='src/auth.php:2 的角色来源缺少服务端重新核验。')]
    decision = PlannerDecision(
        goal_state='continue', basis_summary='采纳线索并直接核对它点名的源码。',
        tasks=[{**proposal('lead-check'), 'target_symbols': [], 'direction_ids': ['lead-cookie']}])
    validated = _validate_planner_decision(decision, project_map, [], policy=AgentPolicy(),
                                           workflow_policy='discovery_first', directions=directions)
    refs = {ref.path: ref for ref in validated.tasks[0].source_refs}
    assert 'src/auth.php' in refs
    assert refs['src/auth.php'].reason == 'adopted_direction_source'
    assert 'public/index.php' in refs
    allowed = PlannerDecision(
        goal_state='continue', basis_summary='把线索点名的路径放进任务窗口再派工。',
        tasks=[{**proposal('lead-check', path='src/auth.php', start=1, end=2), 'target_symbols': [],
                'direction_ids': ['lead-cookie']}])
    validated = _validate_planner_decision(allowed, project_map, [], policy=AgentPolicy(),
                                           workflow_policy='discovery_first', directions=directions)
    assert validated.tasks[0].direction_ids == ['lead-cookie']


def test_lead_drain_page_surfaces_leads_beyond_the_summary_cap(exhaustive):
    from tests.test_goal_tasks import make_worker
    store, repo, run = exhaustive
    for index in range(6):
        capture(exhaustive, text=f'public/index.php:{index + 1} 第{index}条独立边界线索。', key=f'capture-{index}')
    worker = make_worker(store, repo)
    page = worker._lead_drain_page(run['id'])
    assert page['total'] == 6
    assert len(page['leads']) == 6
    assert all(lead['id'].startswith('dir_') and lead['paths'] for lead in page['leads'])
    # Text leads carry the worker-read span, so review-stage triage can settle
    # them without fabricating a Planner navigation as evidence.
    assert all(lead['review_evidence'] for lead in page['leads'])
    assert all(ref['path'] == 'public/index.php' for lead in page['leads'] for ref in lead['review_evidence'])


def test_risk_review_payload_names_current_findings_and_supported_needs_one(exhaustive):
    store, repo, run = exhaustive
    frozen = freeze(store.get_project_map(run['id']), {'focus_scope': 'all'}, run['snapshot_id'])
    operation = next(item for item in frozen['items'] if item['path'] == 'src/files.php')
    spec = {**run['task_spec'], 'risk_coverage_policy': 'bounded-v1', 'risk_obligation_set': frozen}
    store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(spec), run['id']))
    run = store.get_run(run['id'])
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue',
                               basis_summary='读取风险操作及其实际上下文。', tasks=[proposal('risk-read')])
    task = store.claim_ready_task(run['id'], 'worker')
    store.resolve_task_attempt(task['id'], 'worker', outcome='no_evidence', result={
        'outcome': 'no_evidence', 'summary': '已读取实际文件操作及其鉴权上下文。', 'remaining_work': []},
        usage={}, seen=[dict(path=operation['path'], start_line=1, end_line=operation['line'] + 1)],
        terminal_reason='completed')
    finding = {**_conclusion_finding(run), 'id': 'finding-risk', 'fingerprint': 'finding-risk',
               'vulnerability_type': 'path_traversal',
               'primary_location': dict(path=operation['path'], line=operation['line']),
               'evidence': [dict(path=operation['path'], start_line=1, end_line=operation['line'])]}
    store.add_finding(finding)
    candidate = next(item for item in store.risk_review_candidates(run['id']) if item['item_id'] == operation['id'])
    entry = candidate['payload']['findings'][0]
    assert entry['finding_id'] == 'finding-risk' and entry['primary_exact'] is True
    assert entry['evidence_covers_operation'] is True
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    risk_item = next(item for item in batch['items'] if item['item_id'] == operation['id'])
    finding_item = next(item for item in batch['items'] if item['kind'] == 'finding')
    ref = risk_item['payload']['evidence'][0]['range']
    focus = {'objective_ref': 'objective-main', 'relation': 'relevant',
             'rationale': '入口参数直接进入未受约束的文件读取操作，属于本次全量审计目标。',
             'evidence': [dict(path=operation['path'], start_line=ref['start'], end_line=ref['end'])]}
    decisions = [
        dict(item_id=finding_item['item_id'], revision=finding_item['revision'], decision='needs_evidence',
             rationale='该结论的具体影响仍需复核，先保留不并入风险结算。'),
        dict(item_id=risk_item['item_id'], revision=risk_item['revision'], decision='resolve',
             rationale='已读取实际危险操作，需以真实结论证明该义务成立。',
             risk_outcome='supported', focus=focus),
    ]
    with pytest.raises(ValueError, match='finding_ids'):
        store.validate_review_decisions(run['id'], batch, decisions)
    decisions[1]['finding_ids'] = ['finding-risk']
    validated = store.validate_review_decisions(run['id'], batch, decisions)
    assert validated[1]['finding_ids'] == ['finding-risk']
    # A stale or unrelated finding ID cannot settle the operation either.
    decisions[1]['finding_ids'] = ['not-in-this-run']
    with pytest.raises(ValueError, match='当前有效'):
        store.validate_review_decisions(run['id'], batch, decisions)


def test_chain_rooted_finding_can_support_the_command_sink_it_reaches(exhaustive):
    """A deserialization chain owns a sink line that is not its primary coordinate."""
    from audit.risk_coverage import freeze
    store, repo, run = exhaustive
    frozen = freeze(store.get_project_map(run['id']), {'focus_scope': 'all'}, run['snapshot_id'])
    operation = next(item for item in frozen['items'] if item['path'] == 'src/files.php')
    spec = {**run['task_spec'], 'risk_coverage_policy': 'bounded-v1', 'risk_obligation_set': frozen}
    store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(spec), run['id']))
    run = store.get_run(run['id'])
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue',
                               basis_summary='读取风险操作及其实际上下文。', tasks=[proposal('risk-read')])
    task = store.claim_ready_task(run['id'], 'worker')
    store.resolve_task_attempt(task['id'], 'worker', outcome='no_evidence', result={
        'outcome': 'no_evidence', 'summary': '已读取实际文件操作及其调用链上下文。', 'remaining_work': []},
        usage={}, seen=[dict(path=operation['path'], start_line=1, end_line=operation['line'] + 1)],
        terminal_reason='completed')
    basename = operation['path'].rsplit('/', 1)[-1]
    chain = {**_conclusion_finding(run), 'id': 'finding-chain', 'fingerprint': 'finding-chain',
             'vulnerability_type': 'insecure_deserialization',
             'primary_location': dict(path='src/auth.php', line=2),
             'dangerous_operation': f"{basename}:{operation['line']} 由上级利用链触发的操作",
             'evidence': [dict(path='src/auth.php', start_line=1, end_line=2),
                          dict(path=operation['path'], start_line=1, end_line=operation['line'])]}
    store.add_finding(chain)
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    risk_item = next(item for item in batch['items'] if item['item_id'] == operation['id'])
    current = {item['item_id']: json.loads(json.dumps(item)) for item in store._review_candidates(run['id'], 'final')}
    current[operation['id']]['payload']['obligation']['risk'] = 'command_injection'
    ref = risk_item['payload']['evidence'][0]['range']
    focus = {'objective_ref': 'objective-main', 'relation': 'relevant',
             'rationale': '上级利用链的落点是本项系统命令执行操作，属于本次全量审计目标。',
             'evidence': [dict(path=operation['path'], start_line=ref['start'], end_line=ref['end'])]}
    decisions = [dict(item_id=item['item_id'], revision=item['revision'], decision='needs_evidence',
                      rationale='该结论的具体影响仍需复核，先保留不并入风险结算。')
                 for item in batch['items'] if item['kind'] == 'finding']
    decisions.append(dict(item_id=risk_item['item_id'], revision=risk_item['revision'], decision='resolve',
                          rationale='链根因结论已明确写出并实际覆盖本项操作行。',
                          risk_outcome='supported', finding_ids=['finding-chain'], focus=focus))
    validated = store.validate_review_decisions(run['id'], batch, decisions, current_items=current.values())
    assert next(d for d in validated if d['item_id'] == risk_item['item_id'])['finding_ids'] == ['finding-chain']


def test_triage_leads_can_be_settled_alongside_an_active_final_review_batch(exhaustive, monkeypatch):
    from audit import agent
    from audit.config import ModelConfig
    from audit.runtime import AgentPolicy
    from tests.code_model import ModelFactory
    store, repo, run = exhaustive
    lead, = capture(exhaustive, observation=dict(kind='security_boundary', title='会话校验观察',
        summary='该处只证明认证门禁存在，按角色覆盖的边界仍待独立判断。', evidence='public/index.php:1-4'))
    store.add_finding({**_conclusion_finding(run), 'id': 'finding-review', 'fingerprint': 'finding-review'})
    store.set_workflow_stage(run['id'], 'review')
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    assert batch and batch['phase'] == 'final'
    request = dict(goal_state='continue', basis_summary='终审当前结论并结算已有观察线索。',
                   review_batch_id=batch['id'],
                   review_decisions=[dict(item_id=item['item_id'], revision=item['revision'],
                                          decision='needs_evidence',
                                          rationale='该结论仍需补充实际源码证据后再独立判断。')
                                     for item in batch['items']],
                   direction_updates=[dict(direction_id=lead['id'], action='triage',
                                           triage_outcome='no_evidence',
                                           rationale_summary='引用观察自带的读取区间确认该风险已有实际防护。')])
    factory = ModelFactory({'planner_publish': [json.dumps(request, ensure_ascii=False)]})
    monkeypatch.setattr(agent, 'build_code_model', factory)
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    context = {**store.list_planner_context(run['id'], project_map=store.get_project_map(run['id'])),
               'review_batch': batch}
    result = asyncio.run(agent.plan_audit_frontier(
        project_map=store.get_project_map(run['id']), run_context=context, task=run['task_spec'],
        round_no=1, config=ModelConfig(model='offline-replay', base_url='https://example.invalid', api_key='test'),
        budgets={'responses': 8, 'tools': 12, 'seconds': 8}, policy=AgentPolicy(request_seconds=.5),
        repository=repo, snapshot_id=run['snapshot_id'], allowed_paths=set(run['scope']),
        pins=store, run_id=run['id'], plan_id=plan['id']))
    assert result['decision'], result
    assert result['decision']['direction_updates'][0]['action'] == 'triage'
    assert result['decision']['review_batch_id'] == batch['id']
