"""Regression tests for host pagination, durable correction and action boundaries."""
import asyncio
import copy
import json
import time
import threading
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from audit import agent
from audit.actions import ActionIssue, check_action
from audit.config import ModelConfig
from audit.executor import build_executor
from audit.review_input import access_complete, bounded_item
from audit.review_transport import reading_work
from audit.runtime import AgentPolicy, StopAudit
from audit.schemas import PlannerDecision
from audit.structured_output import drive_structured_phase
from audit.submission import bind_review_submission, review_contract, review_schema
from tests.code_model import Answer, Host, Phase, ScriptedCodeModel, code
from tests.test_host_queue import hosted, add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_review_input_repair import decisions


def paged_batch(hosted):
    store, repo, run = hosted
    add_claim(store, run, 1)
    store._write('UPDATE findings SET summary=?', ('必须完整传送的原文。' * 2000,))
    return store, repo, run, store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)


def test_peer_coordinates_legal_actions_and_field_hierarchy_survive_paging():
    raw = dict(kind='finding', item_id='primary', revision='rev', payload={
        'comparison_candidates': [dict(item_id='peer-one', finding_id='finding-one', revision='peer-rev', summary='正文' * 6000)],
        'evidence': [dict(path='entry.php', range=dict(start=3, end=5))]})
    item = bounded_item(raw, limit=1000)
    assert 'comparison_candidates' not in item['payload']
    contract = review_contract(dict(id='batch', phase='integration', items=[item]))
    assert contract['items'][0]['peer_comparison_contract'][0]['item_id'] == 'peer-one'
    assert 'accept' not in contract['items'][0]['allowed_decisions']
    assert 'verification_reviews' in contract['field_hierarchy']['top_level']
    assert 'verification_reviews' not in contract['field_hierarchy']['review_decisions[]']
    assert not access_complete(item)


def test_host_fills_only_unread_gaps_and_restores_typed_facts(hosted):
    store, repo, run, batch = paged_batch(hosted)
    item, part = batch['items'][0], batch['items'][0]['paged_fields'][0]
    for offset in [0, *range(2048, part['characters'], 1024)]:
        store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], offset, repository=repo)
    active = store.active_review_batch(run['id'])
    assert reading_work(active['items'])['characters'] == 1024
    materialized = store.materialize_review_batch(run['id'], batch['id'], repository=repo)
    assert materialized['items'][0]['payload']['summary'] == '必须完整传送的原文。' * 2000
    assert all(access_complete(i) for i in store.active_review_batch(run['id'])['items'])
    assert reading_work(store.active_review_batch(run['id'])['items'])['pages'] == 0
    store.validate_review_decisions(run['id'], materialized, decisions(batch))


def test_pause_releases_lease_but_keeps_exact_cursors_and_fences_old_callbacks(hosted):
    store, repo, run, batch = paged_batch(hosted)
    item, part = batch['items'][0], batch['items'][0]['paged_fields'][0]
    store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], 0, repository=repo)
    store._write('UPDATE run_execution_state SET claim_epoch=claim_epoch+1 WHERE run_id=?', (run['id'],))
    epoch = run['execution_epoch'] + 1
    resumed = store.prepare_review_batch(run['id'], 'final', epoch, repo)
    assert resumed['id'] != batch['id']
    assert resumed['items'][0]['read_ranges'][part['field']] == [[0, 1024]]
    with pytest.raises(ValueError, match='失效'):
        store.read_review_input(run['id'], batch['id'], item['item_id'], part['field'], 1024, repository=repo)
    full = store.materialize_review_batch(run['id'], resumed['id'], repository=repo)
    assert full['items'][0]['revision'] == item['revision']


def test_oversize_or_deadline_never_opens_semantic_gate(hosted):
    store, repo, run, batch = paged_batch(hosted)
    with pytest.raises(StopAudit, match='超过审查输入窗口'):
        store.materialize_review_batch(run['id'], batch['id'], repository=repo, max_bytes=100)
    assert not access_complete(store.active_review_batch(run['id'])['items'][0])
    with pytest.raises(StopAudit, match='禁止进入判决'):
        store.materialize_review_batch(run['id'], batch['id'], repository=repo, deadline=time.monotonic() - 1)
    with pytest.raises(ValueError, match='完整审查'):
        store.validate_review_decisions(run['id'], batch, decisions(batch))


def test_changed_derived_facts_expire_the_lease_without_reusing_its_cursor(hosted, monkeypatch):
    from audit import review_store
    store, repo, run = hosted
    add_claim(store, run, 1)
    monkeypatch.setattr(review_store, 'related_claim_facts', lambda *a, **k: [dict(summary='原文' * 20000)])
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    field = 'payload.related_claims'
    store.read_review_input(run['id'], batch['id'], item['item_id'], field, 0, repository=repo)
    monkeypatch.setattr(review_store, 'related_claim_facts', lambda *a, **k: [dict(summary='变化原文' * 20000)])
    with pytest.raises(StopAudit, match='旧租约失效'):
        store.materialize_review_batch(run['id'], batch['id'], repository=repo)
    assert store.active_review_batch(run['id']) is None
    renewed = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    assert renewed['id'] != batch['id']
    assert not renewed['items'][0].get('read_ranges', {}).get(field)


def test_related_host_failure_is_deferred_instead_of_repeatedly_split(hosted):
    from tests.test_recent_final_review_repair import peer_claims
    store, repo, run = hosted
    run = peer_claims(store, run, 2)
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    store.defer_review_batch(run['id'], batch['id'], '宿主输入不能容纳关联组', split=True)
    assert store.list_review_batches(run['id'])[-1]['status'] == 'deferred'
    assert store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo) is None
    assert sum(map(len, store.review_batches_pending(run['id'], 'final', repo))) == 2


def test_stage_schema_binds_host_ids_and_rejects_nested_reviews(hosted):
    store, repo, run = hosted
    add_claim(store, run, 1, verified=True)
    batch = {**store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo), 'phase': 'integration'}
    schema = review_schema(PlannerDecision.model_json_schema(), batch)
    branch = schema['properties']['review_decisions']['items']['anyOf'][0]
    assert 'accept' not in branch['properties']['decision']['enum']
    assert branch['properties']['item_id']['const'] == batch['items'][0]['item_id']
    assert schema['properties']['verification_reviews']['maxItems'] == 0
    minimal = dict(basis_summary='真实的逐项判读依据', review_decisions=[dict(decision='retain', rationale='依据已读取源码保留本项等待终审。')])
    value = bind_review_submission(minimal, batch)
    assert value['review_decisions'][0]['revision'] == batch['items'][0]['revision']
    assert value['review_batch_id'] == batch['id']
    bad = copy.deepcopy(minimal)
    bad['review_decisions'][0]['decision'] = 'accept'
    with pytest.raises(ValueError, match='只能为'):
        bind_review_submission(bad, batch)
    bad = copy.deepcopy(minimal)
    bad['review_decisions'][0]['verification_reviews'] = []
    with pytest.raises(ValidationError, match='verification_reviews'):
        PlannerDecision.model_validate(bind_review_submission(bad, batch))
    bad = copy.deepcopy(minimal)
    bad['review_decisions'][0]['revision'] = 'invented'
    with pytest.raises(ValueError, match='冻结版本'):
        bind_review_submission(bad, batch)


def test_correction_allowance_survives_split_new_round_and_epoch(hosted):
    store, repo, run, batch = paged_batch(hosted)
    item = batch['items'][0]
    for index in range(2):
        store.reserve_review_publication(run['id'], batch['id'])
        error = ValueError(f"review_decisions[{item['item_id']}].comparison_assessments[changing-peer-{index}] 缺少判读")
        store.reject_review_publication(run['id'], batch['id'], error)
        if index == 0:
            store.defer_review_batch(run['id'], batch['id'], '改变批次不能刷新额度', split=True)
            store._write('UPDATE run_execution_state SET claim_epoch=claim_epoch+1 WHERE run_id=?', (run['id'],))
            batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'] + 1, repo)
    ledger = store.review_allowances(run['id'], 'final')[(item['item_id'], item['revision'])]
    assert ledger['publications'] == 2 and ledger['consecutive'] == 2 and ledger['exhausted']
    assert list(ledger['errors'].values()) == [2]
    from audit.db import Store
    restarted = Store(store.path)
    try:
        with pytest.raises(StopAudit, match='累计纠错上限'):
            restarted.reserve_review_publication(run['id'], batch['id'])
    finally:
        restarted.close()
    assert store.prepare_review_batch(run['id'], 'final', run['execution_epoch'] + 1, repo) is None
    assert store.review_batches_pending(run['id'], 'final', repo)  # Still honestly unresolved.
    store._write("UPDATE findings SET summary='不同版本的新证据，必须获得独立审查机会。' WHERE run_id=?", (run['id'],))
    fresh = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'] + 1, repo)
    assert fresh and fresh['items'][0]['revision'] != item['revision']
    store.reserve_review_publication(run['id'], fresh['id'])


def test_changing_error_types_still_have_only_three_publications(hosted):
    store, repo, run, batch = paged_batch(hosted)
    for category in ['invalid_json', 'focus', 'comparison_assessments']:
        store.reserve_review_publication(run['id'], batch['id'])
        store.reject_review_publication(run['id'], batch['id'], ValueError(category))
    with pytest.raises(StopAudit, match='累计纠错上限'):
        store.reserve_review_publication(run['id'], batch['id'])
    assert store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo) is None


def test_native_format_is_explicit_and_strict_schema_keeps_nonnullable_fields():
    async def play(mode):
        host = Host()
        gate = Phase(host, output_model=Answer, phase='planner_publish').gate()
        gate.publication_schema = Answer.model_json_schema()
        model = ScriptedCodeModel(['{"note":"done"}'], gate=gate)
        model.structured_output = mode
        await drive_structured_phase(model, gate, 'JSON output', 'Only known evidence', max_steps=1)
        return model.params[0]['response_format']
    assert asyncio.run(play('compatible')) is None
    assert asyncio.run(play('json_object')) == {'type': 'json_object'}
    native = asyncio.run(play('json_schema'))
    assert native['json_schema']['strict'] is True
    assert native['json_schema']['schema']['additionalProperties'] is False
    assert native['json_schema']['schema']['required'] == ['note']
    assert ModelConfig.from_environ({'LLM_STRUCTURED_OUTPUT': 'json_schema'}).structured_output == 'json_schema'


@pytest.mark.parametrize('probe,kwargs,category', [
    ('print(1)\n' * 81, dict(max_lines=80), 'action_too_large'),
    ('print("' + 'x' * 100 + '")', dict(max_bytes=80), 'action_too_large'),
    ('values = [1,2,3,4,5,6]', dict(max_nodes=8), 'action_too_complex'),
    ('read_source()\n' * 9, dict(tool_names={'read_source'}, tool_limit=8), 'action_tool_limit'),
    ('json.loads(read_source())', dict(text_tools={'read_source'}), 'text_is_not_json'),
    ('raw = read_source()\nparsed = json.loads(raw)', dict(text_tools={'read_source'}), 'text_is_not_json'),
])
def test_action_preflight_bounds_size_calls_and_text_parsing(probe, kwargs, category):
    with pytest.raises(ActionIssue) as failure:
        check_action(probe, ['json'], {}, **kwargs)
    assert failure.value.category == category


def test_runtime_tool_loop_cannot_renew_its_per_action_allowance():
    host = Host({'read_source': 'source'}, policy=AgentPolicy(action_tool_limit=2))
    outcome = Phase(host, specs=agent.PLANNER_TOOLS, output_model=Answer).play([
        code("for i in range(50):\n    print(read_source(path='a.php', start=1, end=1))"),
        code("final_answer({'note':'recovered'})")])
    assert outcome.failure is None
    assert len(host.calls) == 2
    assert host.events_of('agent_parse_error')[0]['category'] == 'action_tool_limit'


def test_timed_out_action_cannot_borrow_the_next_actions_tool_table(monkeypatch):
    from smolagents.tools import Tool
    from smolagents.local_python_executor import ExecutionTimeoutError
    from audit import executor as executor_module
    entered, release = threading.Event(), threading.Event()
    calls, captured = [], []
    evaluate = executor_module.evaluate_python_code
    def capture(*args, **kwargs):
        if 'later_tool' in kwargs['static_tools']:
            captured.append(kwargs['static_tools']['later_tool'])
        return evaluate(*args, **kwargs)
    monkeypatch.setattr(executor_module, 'evaluate_python_code', capture)
    class WaitingTool(Tool):
        name, description, inputs, output_type = 'wait_tool', 'Controlled timeout probe.', {}, 'string'
        def forward(self):
            calls.append('entered')
            entered.set()
            release.wait(2)
            return 'released'
    class LaterTool(Tool):
        name, description, inputs, output_type = 'later_tool', 'Late dispatch probe.', {}, 'string'
        def forward(self):
            calls.append('late')
            return 'late'
    policy = AgentPolicy(code_seconds=.05)
    executor = build_executor(policy)
    gate = SimpleNamespace(execution=SimpleNamespace(policy=policy), action_diagnostics={}, action_issue=None, closed=False)
    executor.gate_reader = lambda: gate
    executor.send_tools({'wait_tool': WaitingTool(), 'later_tool': LaterTool()})
    try:
        with pytest.raises(ExecutionTimeoutError, match='maximum execution time'):
            executor('wait_tool()\nlater_tool()')
        assert entered.is_set()
        # A later short action cannot grant the abandoned thread another allowance.
        executor('value = 1')
        with pytest.raises(ActionIssue, match='已结束'):
            captured[0]()
    finally:
        release.set()
    assert calls == ['entered']


def test_bad_text_parse_is_rejected_before_any_earlier_tool_dispatch():
    host = Host({'read_source': 'plain source'})
    outcome = Phase(host, specs=agent.PLANNER_TOOLS, output_model=Answer).play([
        code("read_source(path='a.php', start=1, end=1)\nraw = read_source(path='a.php', start=1, end=1)\njson.loads(raw)"),
        code("final_answer({'note':'recovered'})")])
    assert outcome.failure is None and host.calls == []
    assert host.events_of('agent_parse_error')[0]['category'] == 'text_is_not_json'
