"""Independent root/sink coordinates, useful correction hints, and schema parity."""
import asyncio
import copy
import json

import pytest

from audit import agent
from audit.role_policy import POLICY, PREVIOUS_POLICY, validate_assessment, worker_contract
from audit.runtime import AgentPolicy
from audit.schemas import CreateRunRequest, GoalAssessment, TaskFinding
from audit.submission import worker_evidence_reference
from audit.toolkit import FinalAnswerTool
from tests.code_model import ModelFactory, final_answer
from tests.test_worker_strategies import CONFIG, Repository, UNIT, assessment
from tests.test_worker_evidence_roles import owned, exhaustive, hosted, state  # noqa: F401
from tests.test_audit_directions import commit
from tests.test_goal_tasks import proposal


def receipts(finding):
    return [node['evidence'] for node in finding['dataflow']]


@pytest.mark.parametrize('example', worker_evidence_reference()['examples'], ids=lambda x: x['case'])
def test_reference_examples_validate_without_moving_the_root(example):
    finding = TaskFinding.model_validate(example['finding']).model_dump()
    original = copy.deepcopy(finding)
    validate_assessment(dict(role_policy=POLICY), dict(findings=[finding]), receipts(finding), {})
    assert finding == original


def boundary():
    return copy.deepcopy(worker_evidence_reference()['examples'][2]['finding'])


def test_v1_keeps_its_frozen_sink_rule_and_v2_accepts_an_explicit_separate_root():
    claim = boundary()
    with pytest.raises(ValueError, match='sink.*primary_location'):
        validate_assessment(dict(role_policy=PREVIOUS_POLICY), dict(findings=[claim]), receipts(claim), {})
    validate_assessment(dict(role_policy=POLICY), dict(findings=[claim]), receipts(claim), {})
    assert 'sink 节点须覆盖 primary_location' in worker_contract(dict(role_policy=PREVIOUS_POLICY))
    assert '不要求等于最终 sink' in worker_contract(dict(role_policy=POLICY))


@pytest.mark.parametrize('change', ['no_root', 'wrong_root', 'duplicate_root', 'no_sink', 'unread_root'])
def test_separate_root_does_not_remove_source_or_operation_requirements(change):
    claim = boundary()
    seen = copy.deepcopy(receipts(claim))
    if change == 'no_root':
        claim['dataflow'][1]['kind'] = 'protection'
    elif change == 'wrong_root':
        claim['dataflow'][1]['evidence'] = claim['dataflow'][0]['evidence']
    elif change == 'duplicate_root':
        claim['dataflow'].append(copy.deepcopy(claim['dataflow'][1]))
    elif change == 'no_sink':
        claim['dataflow'].pop()
    else:
        seen.pop(1)
    with pytest.raises(ValueError):
        validate_assessment(dict(role_policy=POLICY), dict(findings=[claim]), seen, {})


def test_error_names_the_failed_finding_and_shows_both_coordinates():
    good = worker_evidence_reference()['examples'][0]['finding']
    bad = boundary()
    bad['dataflow'][1]['kind'] = 'protection'
    with pytest.raises(ValueError) as exc:
        validate_assessment(dict(role_policy=POLICY), dict(findings=[good, bad]), receipts(good)+receipts(bad), {})
    message = str(exc.value)
    assert 'findings[1]' in message and 'findings[0]' not in message
    assert 'demo/guard.php:5-5' in message and 'demo/action.php:9-9' in message
    assert 'root_cause' in message and '不要移动主定位' in message


def test_one_correction_reports_multiple_bad_findings():
    bad = boundary()
    bad['dataflow'][1]['kind'] = 'protection'
    with pytest.raises(ValueError) as exc:
        validate_assessment(dict(role_policy=POLICY), dict(findings=[bad, copy.deepcopy(bad)]), receipts(bad), {})
    assert 'findings[0]' in str(exc.value) and 'findings[1]' in str(exc.value)


@pytest.mark.parametrize('field, items', [
    ('observations', [dict(follow_up=True), dict(follow_up=False)]),
    ('direction_results', [dict(outcome='needs_evidence'), dict(outcome='no_evidence')]),
])
def test_missing_disproof_feedback_identifies_the_item_and_required_fields(field, items):
    with pytest.raises(ValueError) as exc:
        validate_assessment(dict(role_policy=POLICY), {field: items}, [], {})
    message = str(exc.value)
    assert field+'[1].disproof' in message
    assert all(name in message for name in ['basis', 'rationale', 'evidence'])


def test_live_schema_examples_and_terminal_tool_share_the_same_contract():
    schema = agent._worker_publication_schema(2, task=dict(role_policy=POLICY))
    definition = schema['$defs']['TaskFinding']
    assert 'dataflow' in definition['required']
    assert definition['properties']['dataflow']['minItems'] == 2
    assert 'root_cause' in schema['$defs']['FlowNode']['properties']['kind']['enum']
    GoalAssessment.model_validate(schema['examples'][0])
    tool = FinalAnswerTool.for_model(None, GoalAssessment, 'GoalAssessment', schema=schema)
    assert 'worker-dataflow-v2' in tool.description and '根因与操作同处' in tool.description
    assert '所有 demo/' in tool.description
    assert 'dataflow' not in GoalAssessment.model_json_schema()['$defs']['TaskFinding']['required']
    assert 'x-host-evidence-contract' not in agent._worker_publication_schema(2, task=dict(role_policy=PREVIOUS_POLICY))


def test_separate_root_survives_the_sqlite_gate_and_candidate_checkpoint(owned):
    store, _, run = owned
    commit(store, run, tasks=[proposal('cross-file-root')])
    task = store.claim_ready_task(run['id'], 'worker')
    claim = boundary()
    claim['primary_location'] = dict(path='src/auth.php', line=2)
    for node, path, line in zip(claim['dataflow'], ['public/index.php', 'src/auth.php', 'src/files.php'], [4, 2, 4]):
        node['evidence'] = dict(path=path, start_line=line, end_line=line)
    reads = copy.deepcopy(receipts(claim))
    settled = store.resolve_task_attempt(task['id'], 'worker', outcome='achieved', result=dict(
        findings=[claim], candidate_updates=[dict(candidate_id='boundary', status='supported', finding_index=0,
            hypothesis='已经为当前候选分别核对根因位置和下游操作。', primary_location=claim['primary_location'], evidence=reads)]),
        usage={}, seen=reads, terminal_reason='completed')
    assert settled['state'] == 'completed'
    attempt = store.list_task_attempts(task['id'])[0]
    assert attempt['seen'] == reads
    assert attempt['result']['findings'][0]['dataflow'] == claim['dataflow']
    assert settled['result']['candidate_journal'][0]['primary_location'] == claim['primary_location']


@pytest.mark.parametrize('phase', ['task_execute', 'task_publish'])
def test_real_worker_corrects_the_binding_in_place_with_its_original_budget(monkeypatch, phase):
    unit = {**UNIT, 'cleaned_lines': [dict(number=n, text=s) for n, s in enumerate([
        '<?php', "$role = $_COOKIE['role'];", "if ($role === 'admin') {", 'echo private_data(); }'], 1)]}
    bad = assessment(vulnerability_type='auth_bypass', evidence='src/a.php:2-4',
        primary_location=dict(path='src/a.php', line=3),
        dataflow=[dict(kind=kind, evidence=dict(path='src/a.php', start_line=n, end_line=n), explanation=explanation)
          for kind, n, explanation in [('input', 2, '客户端角色直接来自当前请求。'),
            ('protection', 3, '可伪造角色决定敏感数据是否可读。'), ('sink', 4, '错误身份边界放行后输出敏感数据。')]])
    good = copy.deepcopy(bad)
    good['findings'][0]['dataflow'][1]['kind'] = 'root_cause'
    outputs = [final_answer(v) if phase == 'task_execute' else json.dumps(v, ensure_ascii=False) for v in [bad, good]]
    factory = ModelFactory({phase: outputs})
    monkeypatch.setattr(agent, 'build_code_model', factory)
    events = []
    result = asyncio.run(agent.pursue_task_work(repository=Repository(), snapshot_id='snapshot', snapshot_name='demo.zip',
        unit=unit, task=dict(objective='核对真实请求身份边界与敏感数据操作。', success_criteria='保存可核对的输入、根因与操作证据。',
            role_policy=POLICY, require_poc=False), attempt=1, config=CONFIG,
        budgets=dict(responses=6, tools=0, seconds=6), policy=AgentPolicy(
            request_seconds=1, worker_explore_responses=2 if phase == 'task_execute' else 0), on_event=events.append))
    assert result['outcome'] == 'achieved', result
    assert result['usage']['requests'] == 2
    assert factory.phases == [phase, phase]
    assert result['result']['findings'][0]['primary_location'] == dict(path='src/a.php', line=3)
    assert 'worker-dataflow-v2' in factory.prompts[0]
    assert any('findings[0]' in str(e.get('reason') or e.get('hint')) for e in events)
    binding = next(e for e in events if e['kind'] == 'role_contract_bound')
    assert binding['policy'] == POLICY and len(binding['evidence_contract_sha256']) == 64


@pytest.mark.parametrize('policy', [PREVIOUS_POLICY, POLICY])
def test_versioned_evidence_contract_requires_host_queue(policy):
    with pytest.raises(ValueError, match='requires host-queue'):
        CreateRunRequest(snapshot_id='snapshot', task=dict(objective='核对原始源码中实际存在的风险。', role_policy=policy))
