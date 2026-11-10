"""Regression for the failed full run: source publication, review carry and retest."""
import asyncio
import copy
import json
from types import SimpleNamespace

import pytest

from audit.actions import terminal_payload
from audit.config import PocSettings
from audit.codemodel import FINAL_ANSWER_ACCEPTED
from audit.poc_readiness import PocReadinessService
from audit.poc_runner import PocRunnerUnavailable
from audit.role_policy import merge_candidates, planner_schema, validate_planner_actions
from audit.schemas import ContinueRunRequest, PlannerDecision
from tests.code_model import Answer, Host, Phase, code
from tests.test_poc_readiness import Client
from tests.test_worker_evidence_roles import candidate, PATH, LINES
from tests.test_run_continuations import hosted, finish, request  # noqa: F401
from tests.test_review_closure import state  # noqa: F401


class TerminalPhase(Phase):
    def gate(self):
        gate = super().gate()
        gate.accept_terminal_object = True
        return gate


@pytest.mark.parametrize('response', [json.dumps({'note': 'done'}), code("final_answer({'note': 'done'})")])
def test_complete_terminal_object_is_validated_once_without_interpreter(response):
    host = Host({})
    result = TerminalPhase(host, output_model=Answer).play([response])
    assert result.failure is None and result.output == FINAL_ANSWER_ACCEPTED
    assert result.gate.published == Answer(note='done')
    assert len(result.model.requests) == 1 and not result.codes and not host.calls
    assert len(host.events_of('model_response')) == 1


def test_large_literal_publication_does_not_spend_code_action_quota():
    host = Host({})  # Deliberately only 512 code bytes.
    result = TerminalPhase(host, output_model=Answer).play([code('final_answer(' + repr({'note': 'x' * 9000}) + ')')])
    assert result.failure is None and len(result.gate.published.note) == 9000
    assert not result.codes


def test_rejected_terminal_proof_is_corrected_once_with_no_interpreter_or_double_count():
    def refuse(_value):
        if _value.note != 'corrected':
            raise ValueError('未实际读取的证据，不得接受')
        return _value
    host = Host({})
    result = TerminalPhase(host, output_model=Answer, validate=refuse).play([
        json.dumps({'note': 'done'}), json.dumps({'note': 'corrected'})])
    assert result.failure is None and result.gate.published.note == 'corrected'
    assert len(result.model.requests) == 2 and len(host.events_of('terminal_publication_rejected')) == 1
    assert not host.events_of('agent_parse_error')
    assert not host.calls


@pytest.mark.parametrize('response,finish_reason', [
    ('{"note":"done"}', 'length'),
    ('text {"note":"done"}', None),
    (code("print(read_source(path='x')); final_answer({'note': 'done'})"), None),
    (code("final_answer(dict(note='done'))"), None),
    (code("final_answer({'note': 'a', 'note': 'b'})"), None),
    ('{"note":"a","note":"b"}', None),
    ('<code>final_answer({"note":"done"})', None),
])
def test_terminal_transport_never_repairs_or_executes_expressions(response, finish_reason):
    assert terminal_payload(response, finish_reason) is None


def test_pending_hypothesis_reanchors_only_with_old_new_read_evidence():
    spans = [(PATH, 1, 4)]
    old = merge_candidates([], [candidate()], [], spans, LINES)
    moved = {**candidate(), 'primary_location': dict(path=PATH, line=3),
             'reanchor_from': dict(path=PATH, line=4),
             'reanchor_reason': '补读调用关系确认原位置只是汇点，第三行才是同一假设的根因。',
             'evidence': [dict(path=PATH, start_line=3, end_line=4)]}
    corrected = merge_candidates(old, [moved], [], spans, LINES)
    assert corrected[0]['anchor_history'][0]['primary_location']['line'] == 4
    for change in ({'reanchor_from': dict(path=PATH, line=2)}, {'reanchor_reason': ''},
                   {'evidence': [dict(path=PATH, start_line=3, end_line=3)]}):
        with pytest.raises(ValueError):
            merge_candidates(old, [{**moved, **change}], [], spans, LINES)
    with pytest.raises(ValueError, match='本次实际读取'):
        merge_candidates(old, [moved], [], [(PATH, 3, 3)], LINES)


def test_legacy_schema_and_prevalidation_agree_on_triage():
    schema = planner_schema(PlannerDecision.model_json_schema())
    assert 'triage' not in schema['$defs']['PlannerDirectionUpdate']['properties']['action']['enum']
    update = [dict(action='triage', direction_id='d', triage_outcome='blocked')]
    with pytest.raises(ValueError, match='triage'):
        validate_planner_actions({'exploration_policy': 'legacy'}, direction_updates=update,
                                 directions={'d': {'requirement': 'advisory'}})
    validate_planner_actions({'exploration_policy': 'exhaustive-v1'}, direction_updates=update,
                             directions={'d': {'requirement': 'advisory'}})


def test_transient_health_failure_does_not_skip_entire_queue_and_never_leaks_details():
    class Flaky(Client):
        async def health(self):
            if self.calls == 0:
                self.calls += 1
                raise PocRunnerUnavailable('private-token http://internal')
            return await super().health()
    client = Flaky()
    service = PocReadinessService(SimpleNamespace(poc=PocSettings(runner_url='http://runner')),
                                  client_factory=lambda: client)
    result = asyncio.run(service.check_for_execution('lab30', mode='required'))
    assert result['available'] and result['health_attempts'] == 2 and client.closed == 2
    assert result['health_history'][0]['diagnostic']['category'] == 'connection'
    assert 'private-token' not in json.dumps(result) and 'http://' not in json.dumps(result)


def test_permanent_health_failure_has_finite_attempts():
    client = Client()
    client.healthy = False
    service = PocReadinessService(SimpleNamespace(poc=PocSettings(runner_url='http://runner')),
                                  client_factory=lambda: client)
    result = asyncio.run(service.check_for_execution('lab30', mode='required'))
    assert not result['available'] and client.calls == client.closed == result['health_attempts'] == 3


def test_explicit_high_recall_child_upgrades_policy_without_mutating_frozen_parent(hosted):
    store, _, run = hosted
    finish(store, run)
    frozen = copy.deepcopy(store.frozen_report(run['id']))
    child = store.create_continuation(run['id'], request(mode='audit', audit_policy='exhaustive-v1', require_dynamic=True))
    task = child['task_spec']
    assert task['focus_scope'] == 'all' and task['exploration_policy'] == 'exhaustive-v1'
    assert task['risk_coverage_policy'] == 'bounded-v2' and task['scenario'] is None
    assert task['risk_obligation_set']['version'] == 'risk-obligations/v2'
    assert not task['stop_on_achieved'] and task['audit_focus']['scope'] == 'all'
    assert child['poc_policy']['mode'] == 'required' and child['poc_policy']['required']
    assert child['agent_policy']['worker_max_tokens'] >= 8192
    assert child['execution_summary']['run_usage']['responses'] == 0
    assert store.get_run(run['id'])['task_spec'] == run['task_spec']
    assert store.frozen_report(run['id']) == frozen


def test_unavailable_poc_releases_only_clock_reservation(hosted):
    store, _, run = hosted
    before = store.workflow_state(run['id'])
    # The fixture disables POC; emulate a frozen positive reservation.
    value = json.loads(store._row('SELECT workflow FROM run_execution_state WHERE run_id=?', (run['id'],))[0])
    value['poc_reserved_seconds'] = 600
    store._write('UPDATE run_execution_state SET workflow=? WHERE run_id=?', (json.dumps(value), run['id']))
    assert store.release_unavailable_poc_window(run['id'], {'available': False, 'reason': 'runner_unhealthy'})
    after = store.workflow_state(run['id'])
    assert after['limits'] == before['limits'] and after['used'] == before['used']
    assert after['poc_reserved_seconds'] == 0 and after['poc_window_released']['retry_at'] == 'poc_stage'
    assert not store.release_unavailable_poc_window(run['id'], {'available': False})


@pytest.mark.parametrize('changes', [dict(mode='poc_review', audit_policy='exhaustive-v1'),
                                      dict(mode='review', require_dynamic=True)])
def test_upgrade_requires_explicit_compatible_continuation_mode(changes):
    with pytest.raises(ValueError):
        ContinueRunRequest(request_id='invalid-mode', **changes)


def test_required_retest_checks_environment_before_creating_or_notifying(hosted, monkeypatch):
    from fastapi.testclient import TestClient
    from audit import app as app_module
    from audit.poc import PocVerifier
    store, repo, run = hosted
    finish(store, run)
    notified = []
    services = SimpleNamespace(store=store, repository=repo, bus=object(), settings=object(),
        worker=SimpleNamespace(notify=lambda: notified.append(True)))
    monkeypatch.setattr(app_module.app.state, 'services', services, raising=False)
    async def unavailable(self, _run):
        return dict(available=False, reason='runner_unhealthy', message='隔离环境不可用')
    monkeypatch.setattr(PocVerifier, 'preflight', unavailable)
    client = TestClient(app_module.app)
    try:
        # A review-only request would not call preflight; here even an empty source
        # continuation must refuse before committing an unusable required-POC child.
        response = client.post(f'/api/runs/{run["id"]}/continuation', json=request(
            mode='audit', audit_policy='exhaustive-v1', require_dynamic=True, model_profile_id='original'))
    finally:
        client.close()
    assert response.status_code == 409 and response.json()['detail']['code'] == 'poc_not_ready'
    assert not notified and store._row('SELECT COUNT(*) FROM runs')[0] == 1
