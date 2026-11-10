"""Real lifecycle/client/coordinator paths; scripted failures, no model or runner jobs."""
import asyncio
import copy
import json
from types import SimpleNamespace

import httpx
import pytest

from audit import poc, worker as worker_module
from audit.execution_state import CURRENT_EXECUTION
from audit.frozen_reports import materialize
from audit.poc import PocVerifier
from audit.poc_context import confirm_closed
from audit.poc_runner import PocRunnerClient, PocRunnerError, PocRunnerUnavailable
from audit.runtime import StopAudit
from audit.schemas import PocVerificationResult
from tests.test_host_queue import hosted, add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_run_continuations import decisions, finish, request
from tests.test_goal_tasks import make_worker
from tests.test_poc_agent import FakeClient, FakeStore, FakeBus, FINDING, FINDING_TWO, CONFIG, make_reset_verifier


def status(context_id='ctx', state='closed', active=0, pending_jobs=0):
    return dict(context_id=context_id, state=state, active=active, pending_jobs=pending_jobs)


class LifecycleClient:
    def __init__(self, close_results, get_results):
        self.close_results = iter(close_results)
        self.get_results = iter(get_results)
        self.calls = []
        self.reconnects = 0

    async def close_context(self, context_id):
        self.calls.append(('DELETE', context_id))
        result = next(self.close_results)
        if isinstance(result, BaseException): raise result
        return result

    async def context_status(self, context_id):
        self.calls.append(('GET', context_id))
        result = next(self.get_results)
        if isinstance(result, BaseException): raise result
        return result

    async def reset_connection(self):
        self.reconnects += 1


def test_lost_close_ack_and_first_failed_read_recover_before_next_reset():
    client = LifecycleClient([TimeoutError(), status(state='closing')], [PocRunnerUnavailable('private secret URL'), status()])
    result = asyncio.run(confirm_closed(client, 'ctx', interval=.001))
    assert result['state'] == 'closed' and result['acknowledged']
    assert result['close_attempts'] == 2 and result['status_attempts'] == 2
    assert client.reconnects == 2 and {ident for _, ident in client.calls} == {'ctx'}
    assert 'private' not in json.dumps(result) and 'URL' not in json.dumps(result)


def test_successful_close_ack_is_authoritative_without_an_extra_fallible_get():
    client = LifecycleClient([status()], [])
    result = asyncio.run(confirm_closed(client, 'ctx'))
    assert result['state'] == 'closed' and client.calls == [('DELETE', 'ctx')]


def test_real_http_client_recovers_delete_applied_before_response_timeout():
    async def scenario():
        state = {'closed': False}
        calls = []
        async def handler(request):
            calls.append((request.method, request.url.path))
            if request.method == 'DELETE':
                state['closed'] = True
                await asyncio.sleep(1)  # Cancel the acknowledgement, not its applied effect.
            return httpx.Response(200, json=status(state='closed' if state['closed'] else 'open'))
        client = PocRunnerClient('http://runner.invalid', transport=httpx.MockTransport(handler))
        try:
            result = await confirm_closed(client, 'ctx', timeout=.5, request_timeout=.01, interval=.001)
            assert result['state'] == 'closed' and not result['acknowledged']
            assert [method for method, _ in calls] == ['DELETE', 'GET']
            assert result['diagnostics'][0]['category'] == 'timeout'
        finally: await client.aclose()
    asyncio.run(scenario())


def test_first_failed_get_does_not_cancel_the_remaining_confirmation_window():
    client = LifecycleClient([status(state='closing')], [PocRunnerUnavailable('temporary'), status()])
    result = asyncio.run(confirm_closed(client, 'ctx', interval=.001))
    assert result['state'] == 'closed' and result['status_attempts'] == 2


def test_get_404_after_lost_create_cannot_replace_the_delete_tombstone():
    class Missing(LifecycleClient):
        async def close_context(self, _id): raise PocRunnerUnavailable('delete not delivered')
        async def context_status(self, _id): return {**status(), 'was_unknown': True}
    result = asyncio.run(confirm_closed(Missing([], []), 'ctx', interval=.001))
    assert result['state'] == 'unknown' and not result['acknowledged']


def test_older_runner_unknown_delete_ack_is_normalized_as_a_fenced_context():
    async def scenario():
        calls = []
        def handler(request):
            calls.append(request.method)
            return httpx.Response(200, json=dict(context_id='ctx', state='closed', active=0, was_unknown=True))
        client = PocRunnerClient('http://runner.invalid', transport=httpx.MockTransport(handler))
        try:
            result = await confirm_closed(client, 'ctx')
            assert result['state'] == 'closed' and result['acknowledged'] and calls == ['DELETE']
        finally: await client.aclose()
    asyncio.run(scenario())


@pytest.mark.parametrize('value', [status(state='closing', active=1), status(state='closing', pending_jobs=1), status(state='unresolved')])
def test_real_busy_or_unresolved_context_never_grants_reset(value):
    class Busy(LifecycleClient):
        async def context_status(self, _context_id): return value
    client = Busy([value], [])
    result = asyncio.run(confirm_closed(client, 'ctx', timeout=.015, interval=.001))
    assert result['state'] in {'busy', 'unresolved'}
    assert result['active'] or result['pending_jobs'] or result['state'] == 'unresolved'


@pytest.mark.parametrize('ack', [status(context_id='foreign'), {'context_id':'ctx','state':'closed'},
                                status(active=1), status(active=False), status(pending_jobs=-1)])
def test_foreign_or_malformed_closed_ack_cannot_authorize_reuse(ack):
    class Invalid(LifecycleClient):
        async def close_context(self, _id): return ack
        async def context_status(self, _id): return ack
    result = asyncio.run(confirm_closed(Invalid([], []), 'ctx', interval=.001))
    assert result['state'] == 'unknown' and not result['acknowledged']


def test_unavailable_and_auth_failures_have_finite_attempts_and_safe_metadata():
    class Down(LifecycleClient):
        async def close_context(self, _id): raise PocRunnerUnavailable('token=secret')
        async def context_status(self, _id): raise PocRunnerUnavailable('token=secret')
    result = asyncio.run(confirm_closed(Down([], []), 'ctx', timeout=15, interval=.001))
    assert result['state'] == 'unknown' and result['close_attempts'] == 2 and result['status_attempts'] == 2
    assert result['elapsed_ms'] < 500
    client = LifecycleClient([PocRunnerError('Bearer private', status_code=401)], [])
    result = asyncio.run(confirm_closed(client, 'ctx', interval=.001))
    assert result['state'] == 'unknown' and result['authorization_failed']
    assert not result['status_attempts'] and not client.reconnects
    assert 'private' not in json.dumps(result)


def test_two_findings_recover_first_cleanup_and_preserve_reset_order(tmp_path, monkeypatch):
    order = []
    class Client(FakeClient):
        def __init__(self):
            super().__init__()
            self.close_calls = 0
            self.get_calls = 0
        async def close_context(self, context_id):
            self.close_calls += 1
            order.append(('close', context_id))
            if self.close_calls == 1: raise TimeoutError('lost acknowledgement')
            return status(context_id)
        async def context_status(self, context_id):
            self.get_calls += 1
            if self.get_calls == 1: raise PocRunnerUnavailable('temporary')
            return status(context_id)
        async def create_context(self, **kwargs):
            order.append(('create', kwargs['context_id']))
            return await super().create_context(**kwargs)
    async def fake_agent(**kwargs):
        return PocVerificationResult(status='inconclusive', summary='保留实际未决'), 'completed'
    monkeypatch.setattr(poc, 'run_poc_agent', fake_agent)
    client, store, bus = Client(), FakeStore(), FakeBus()
    verifier = make_reset_verifier(tmp_path, store, bus, client, 'unused')
    async def reset(run, finding, policy):
        order.append(('reset', finding['id']))
        return True, {}
    monkeypatch.setattr(verifier, '_reset_target', reset)
    result = asyncio.run(verifier.verify_standing('run-1', [FINDING, FINDING_TWO], {}, model_config=CONFIG))
    assert result['processed'] == 2 and len(client.created) == 2
    assert not verifier._last_context and len(store.records) == 2
    assert bus.kinds().count('poc_context_closed') == 2 and 'poc_target_reset_failed' not in bus.kinds()
    assert [kind for kind, _ in order] == ['reset','create','close','close','reset','create','close']


def test_cancellation_does_not_leave_detached_context_cleanup(tmp_path):
    async def scenario():
        entered, ended = asyncio.Event(), asyncio.Event()
        class Hanging:
            async def close_context(self, _id):
                entered.set()
                try: await asyncio.Future()
                finally: ended.set()
        verifier = PocVerifier.__new__(PocVerifier)
        verifier._context_closures = {}
        task = asyncio.create_task(verifier._close_finding_context({}, {}, None, Hanging(), 'ctx'))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert ended.is_set() and not [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
    asyncio.run(scenario())


@pytest.mark.parametrize('hosted_queue', [True, False])
def test_required_environment_failure_keeps_final_review_and_unresolved_status(hosted, monkeypatch, hosted_queue):
    store, repo, run = hosted
    add_claim(store, run, 1, verified=hosted_queue)
    pending = add_claim(store, run, 2)
    store._write("UPDATE runs SET project_mode='project',poc_policy=? WHERE id=?",
                 (json.dumps(dict(mode='required', enabled=True, required=True)), run['id']))
    finish(store, run)
    before = copy.deepcopy(store.frozen_report(run['id']))
    child = store.create_continuation(run['id'], request(finding_ids=[pending['id']]))
    if not hosted_queue:
        task = {**child['task_spec'], 'orchestration_policy':'rounds-v1'}
        store._write('UPDATE runs SET task_spec=? WHERE id=?', (json.dumps(task), child['id']))
    claimed = store.claim_next_run()
    calls, reviews = [], []
    async def verify(verifier, run_id, findings, verified_for, **kwargs):
        calls.append([f['id'] for f in findings])
        store.set_poc_state(run_id, dict(available=False, reason='target_reset_blocked', message='暂时不能确认关闭'), claimed['execution_epoch'])
        raise StopAudit('environment_unavailable', '暂时不能确认关闭')
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        batch = kwargs['run_context']['review_batch']
        reviews.append(batch['phase'])
        return dict(decision=dict(goal_state='continue', basis_summary='已复核源码，动态未完成保留缺口。',
            review_batch_id=batch['id'], review_decisions=decisions(batch, 'needs_evidence')),
            usage={'requests':1}, terminal_reason='completed')
    monkeypatch.setattr(worker_module.PocVerifier, 'verify_standing', verify)
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    asyncio.run(make_worker(store, repo)._execute(claimed))
    final = store.get_run(child['id'])
    assert final['status'] == 'inconclusive' and len(calls) == 1 and 'final' in reviews
    workflow = final['execution_summary']['workflow']
    assert workflow['stage'] == 'review' and workflow['used']['review'] > 0
    assert workflow['poc_stop']['reason'] == 'target_reset_blocked'
    assert final['execution_summary']['poc']['available'] is False
    assert store.frozen_report(run['id']) == before
    assert len(store.pending_continuation_verifications(child['id'])) == 1
    assert store.has_event(child['id'], 'poc_stage_stopped')
    assert store._row("SELECT COUNT(*) FROM audit_review_batches WHERE run_id=? AND phase='final' AND status='completed'", (child['id'],))[0] > 0
    assert materialize(store, repo, child['id'])['facts']['counts']['pending'] == 2


def test_hard_budget_cannot_be_reclassified_as_an_environment_failure(hosted, monkeypatch):
    store, repo, run = hosted
    add_claim(store, run, 1)
    store._write("UPDATE runs SET project_mode='project' WHERE id=?", (run['id'],))
    finish(store, run)
    child = store.create_continuation(run['id'], request())
    claimed = store.claim_next_run()
    async def verify(*args, **kwargs): raise StopAudit('run_budget_exhausted', '硬预算到期')
    async def planner(**kwargs): raise AssertionError('Cannot open review after hard budget stop')
    monkeypatch.setattr(worker_module.PocVerifier, 'verify_standing', verify)
    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    asyncio.run(make_worker(store, repo)._execute(claimed))
    final = store.get_run(child['id'])
    assert final['execution_summary']['stop_reason']['code'] == 'run_budget_exhausted'
    assert not final['execution_summary']['workflow'].get('poc_stop')
