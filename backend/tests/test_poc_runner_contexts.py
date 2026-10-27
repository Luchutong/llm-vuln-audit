"""Lease, identity and idempotency contracts without a live shop or model."""
import asyncio
import importlib
import json
import sys
import threading
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
runner = importlib.import_module('poc_runner.runner')


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    for name in ('_contexts', '_leases', '_account_baselines', '_jobs', '_cancelled_contexts'):
        monkeypatch.setattr(runner, name, {})
    monkeypatch.setattr(runner, 'WORKDIR', tmp_path)
    monkeypatch.setattr(runner, 'TOKEN', 'test-token')
    monkeypatch.setattr(runner, '_semaphore', asyncio.Semaphore(2))
    state = {'alice': {'username': 'alice', 'role': 'customer', 'balance': '100.00'},
             'bob': {'username': 'bob', 'role': 'customer', 'balance': '100.00'},
             'operator': {'username': 'operator', 'role': 'operator'},
             'admin': {'username': 'admin', 'role': 'admin'}}
    clients = []

    def make_client():
        def respond(request):
            if request.url.path == '/health.php':
                return httpx.Response(200, json={'ok': True})
            if request.url.path == '/auth/login.php':
                from urllib.parse import parse_qs
                identity = parse_qs(request.content.decode())['username'][0]
                return httpx.Response(302, headers={'Set-Cookie': f'SHOPSESSID={identity}; Path=/'})
            cookie = request.headers.get('cookie', '')
            identity = next((name for name in state if f'SHOPSESSID={name}' in cookie), None)
            if request.url.path == '/account/me.php':
                return httpx.Response(200, json=state[identity]) if identity else httpx.Response(401, json={'error': 'guest'})
            return httpx.Response(200, text=identity or 'guest')
        client = httpx.Client(base_url=runner.LAB30_URL, transport=httpx.MockTransport(respond), follow_redirects=False)
        clients.append(client)
        return client

    monkeypatch.setattr(runner, '_lab30_client', make_client)
    yield state
    for client in clients:
        client.close()


def context(finding='f1', ident=''):
    return runner.create_context(runner.ContextRequest(run_id='r1', finding_id=finding, context_id=ident))['context_id']


def test_target_lease_is_exclusive_and_create_is_idempotent(isolated):
    first = context(ident='stable')
    assert context(ident='stable') == first
    with pytest.raises(HTTPException) as error:
        context('f2')
    assert error.value.status_code == 409
    assert runner.close_context(first)['state'] == 'closed'
    assert runner.close_context(first)['state'] == 'closed'
    assert context('f2') != first


def test_identity_cookies_and_guest_are_separate(isolated):
    first = context()
    for identity in ('alice', 'bob', 'operator', 'admin', 'guest'):
        prepared = runner._prepare_sync(context_id=first, identity=identity)
        assert prepared['ok'] is True
        assert prepared['precondition']['actual']['role'] == runner.IDENTITIES[identity][2]
        result = asyncio.run(runner.http_observe(runner.HttpRequest(context_id=first, identity=identity, path='/')))
        assert result['body'] == identity
        assert result['exit_code'] == 0
        assert runner._jobs[result['job_id']]['context_id'] == first
    assert runner._prepared_cookies(first, 'alice')[0]['value'] == 'alice'
    assert runner._prepared_cookies(first, 'bob')[0]['value'] == 'bob'
    assert runner._prepared_cookies(first, 'guest') == []
    runner.close_context(first)
    second = context('f2')
    runner._prepare_sync(context_id=second, identity='alice')
    assert runner._contexts[second]['sessions']['alice']['client'] is not runner._contexts[first]['sessions'].get('alice', {}).get('client')


def test_changed_role_is_blocked_on_the_next_experiment(isolated):
    first = context()
    assert runner._prepare_sync(context_id=first)['ok']
    def promote():
        isolated['alice']['role'] = 'admin'
        return {'status': 'finished', 'exit_code': 0, 'stdout': 'promoted'}
    proof = runner._context_operation(first, 'lab30', lambda ctx: runner._observed_action(ctx, 'alice', promote))
    assert proof['exit_code'] == 0
    assert proof['precondition']['ok'] is True
    assert proof['postcondition']['ok'] is False
    assert proof['state_changes'] == [{'identity': 'alice', 'field': 'role', 'before': 'customer', 'after': 'admin'}]
    runner.close_context(first)
    second = context('f2')
    assert not runner._prepare_sync(context_id=second)['ok']
    called = []
    outcome = runner._context_operation(second, 'lab30', lambda ctx: runner._observed_action(ctx, 'alice', lambda: called.append(True)))
    assert outcome['execution_status'] == 'precondition_failed'
    assert not called
    assert runner._prepare_sync(context_id=second, identity='bob')['ok']


def test_account_mutation_requires_manual_reset(isolated):
    first = context()
    assert runner._prepare_sync(context_id=first)['ok']
    isolated['alice']['balance'] = '1.00'
    runner.close_context(first)
    second = context('f2')
    assert runner._prepare_sync(context_id=second)['precondition']['reason'] == 'target_state_changed_manual_reset_required'
    assert not runner._prepare_sync(context_id=second)['ok'], 'rechecking cannot acknowledge pollution'
    isolated['alice']['balance'] = '100.00'  # explicit simulated manual reset
    assert runner._prepare_sync(context_id=second)['ok']


def test_close_keeps_lease_until_active_action_ends(isolated):
    ident = context()
    started, finish = threading.Event(), threading.Event()
    def operation(_ctx):
        started.set()
        assert finish.wait(5)
    thread = threading.Thread(target=lambda: runner._context_operation(ident, 'lab30', operation))
    thread.start()
    assert started.wait(5)
    assert runner.close_context(ident)['state'] == 'closing'
    with pytest.raises(HTTPException):
        context('f2')
    with pytest.raises(HTTPException):
        runner._context_operation(ident, 'lab30', lambda _: None)
    finish.set()
    thread.join(5)
    assert runner._contexts[ident]['state'] == 'closed'
    context('f2')


def test_restart_preserves_unresolved_lease_without_cookies(isolated, monkeypatch):
    ident = context()
    runner._prepare_sync(context_id=ident)
    journal = (runner.WORKDIR / 'verification-contexts.json').read_text()
    assert 'password' not in journal and 'SHOPSESSID' not in journal
    monkeypatch.setattr(runner, '_contexts', {})
    monkeypatch.setattr(runner, '_leases', {})
    runner._restore_leases()
    assert runner._contexts[ident]['state'] == 'unresolved'
    with pytest.raises(HTTPException):
        runner._prepare_sync(context_id=ident)
    with pytest.raises(HTTPException):
        context('f2')
    with pytest.raises(HTTPException):
        runner.close_context(ident)


def test_jobs_are_queryable_while_running_and_never_resubmitted(isolated, monkeypatch):
    started, finish = threading.Event(), threading.Event()
    executions = []
    def execute(request):
        executions.append(request.job_id)
        started.set()
        assert finish.wait(5)
        return {'job_id': request.job_id, 'status': 'finished', 'exit_code': 0, 'stdout': 'normal attack', 'stderr': ''}
    monkeypatch.setattr(runner, '_execute', execute)
    headers = {'Authorization': 'Bearer test-token'}
    payload = {'job_id': 'stable-job', 'language': 'python', 'script': 'print(1)'}
    with TestClient(runner.app) as client:
        payload['context_id'] = client.post('/v1/verification-contexts', headers=headers, json={'run_id':'r','finding_id':'f'}).json()['context_id']
        responses = []
        thread = threading.Thread(target=lambda: responses.append(client.post('/v1/jobs', headers=headers, json=payload)))
        thread.start()
        assert started.wait(5)
        running = client.get('/v1/jobs/stable-job', headers=headers).json()
        assert running['status'] == 'running'
        duplicate = client.post('/v1/jobs', headers=headers, json=payload)
        assert duplicate.json()['status'] == 'running'
        changed = client.post('/v1/jobs', headers=headers, json={**payload, 'script': 'print(2)'})
        assert changed.status_code == 409
        closing = client.delete('/v1/verification-contexts/' + payload['context_id'], headers=headers)
        assert closing.json()['state'] == 'closing'
        finish.set(); thread.join(5)
        assert responses[0].json()['exit_code'] == 0
        assert executions == ['stable-job']
        assert runner._contexts[payload['context_id']]['state'] == 'closed'


def test_entrypoints_require_valid_context_and_health_advertises_support(isolated):
    assert runner.healthz()['capabilities']['verification_contexts']
    with TestClient(runner.app) as client:
        headers = {'Authorization': 'Bearer test-token'}
        response = client.post('/v1/jobs', headers=headers, json={'language':'python','script':'print(1)'})
        assert response.status_code == 409
        response = client.post('/v1/http', headers=headers, json={'path':'/'})
        assert response.status_code == 409
        response = client.post('/v1/browser/check', headers=headers, json={'path':'/'})
        assert response.status_code == 409


def test_required_account_assertions_are_sticky_and_typed(isolated):
    ident = context()
    state = {'balance': '100.00', 'tier': 'standard'}
    isolated['alice']['tier'] = 'standard'
    assert runner._prepare_sync(context_id=ident, expected_state=state)['ok']
    isolated['alice']['balance'] = '0.00'
    first = runner._prepare_sync(context_id=ident)
    assert not first['ok']
    assert first['precondition']['expected_state'] == state
    assert not runner._prepare_sync(context_id=ident, expected_state={})['ok']
    with pytest.raises(HTTPException):
        runner._prepare_sync(context_id=ident, expected_state={'balance': '0.00'})
    with pytest.raises(HTTPException):
        runner._prepare_sync(context_id=ident, expected_state={'password': 'secret'})
    with pytest.raises(HTTPException):
        runner._prepare_sync(context_id=ident, expected_role='admin')


def test_prepare_login_failure_returns_a_failed_precondition(isolated, monkeypatch):
    client = httpx.Client(base_url=runner.LAB30_URL, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={'ok': True}) if request.url.path == '/health.php' else httpx.Response(401)))
    monkeypatch.setattr(runner, '_lab30_client', lambda: client)
    result = runner._prepare_sync(context_id=context())
    assert not result['ok']
    assert result['precondition']['reason'] == 'identity_preparation_failed'


def test_only_selected_identity_credentials_enter_script_environment(isolated, monkeypatch):
    result = runner._execute(runner.JobRequest(language='python', identity='bob', script='''import os
assert os.environ['LAB30_IDENTITY'] == 'bob'
assert os.environ['LAB30_USER'] == 'bob'
assert os.environ['LAB30_PASSWORD'] == 'Bob123!'
assert 'LAB30_ADMIN_PASSWORD' not in os.environ
assert 'POC_RUNNER_TOKEN' not in os.environ
print('selected-identity-only')
'''))
    assert result['exit_code'] == 0, result['stderr']
    assert result['stdout'].strip() == 'selected-identity-only'


def test_close_unknown_context_persists_a_cancellation_tombstone(isolated, monkeypatch):
    assert runner.close_context('delayed-context')['state'] == 'closed'
    with pytest.raises(HTTPException):
        context(ident='delayed-context')
    # A service restart cannot revive a queued or retried timed-out creation.
    monkeypatch.setattr(runner, '_cancelled_contexts', {})
    runner._restore_leases()
    with pytest.raises(HTTPException):
        context(ident='delayed-context')
    assert not runner._leases
    assert context(ident='fresh-context') == 'fresh-context'


def test_completed_script_kills_its_background_process_group(isolated, monkeypatch):
    import time
    # On a developer host this uid may already own >64 unrelated processes.
    # The production container has a dedicated uid; disable only that host-wide
    # limit in this fork test while retaining the other real child limits.
    original_limit = runner.resource.setrlimit
    monkeypatch.setattr(runner.resource, 'setrlimit', lambda kind, value:
                        None if kind == runner.resource.RLIMIT_NPROC else original_limit(kind, value))
    result = runner._execute(runner.JobRequest(language='python', script='''import subprocess, sys
subprocess.Popen([sys.executable, '-c', "import time;time.sleep(0.5);open('background-ran','w').write('bad')"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print('leader-finished')
'''))
    assert result['status'] == 'finished'
    assert result['process_confirmed_stopped'] is True
    assert result['exit_code'] == 0, result['stderr']
    time.sleep(.7)
    assert not (runner._job_dir(result['job_id']) / 'background-ran').exists()


def test_timed_out_script_is_confirmed_stopped(isolated):
    result = runner._execute(runner.JobRequest(language='python', timeout_seconds=1, script='import time;time.sleep(60)'))
    assert result['status'] == 'timeout'
    assert result['timed_out'] is True
    assert result['process_confirmed_stopped'] is True
    assert result['exit_code'] != 0


def test_uncertain_termination_keeps_context_and_lease_unresolved(isolated, monkeypatch):
    ident = context()
    # The script itself exits normally. Simulate the OS being unable to confirm
    # all process-group members have stopped; no actual process is left running.
    monkeypatch.setattr(runner, '_terminate_process_group', lambda process: False)
    result = runner._context_operation(ident, 'lab30', lambda ctx: runner._observed_action(ctx, 'alice', lambda:
        runner._execute(runner.JobRequest(language='python', script='print(1)', context_id=ident))))
    assert result['status'] == 'unresolved'
    assert result['exit_code'] is None
    assert runner._leases['lab30'] == ident
    assert runner._contexts[ident]['state'] == 'unresolved'
    with pytest.raises(HTTPException):
        runner.close_context(ident)
    with pytest.raises(HTTPException):
        context('f2')


def test_browser_cookies_round_trip_for_single_label_host_and_logout(isolated):
    ident = context()
    assert runner._prepare_sync(context_id=ident, identity='alice')['ok']
    assert runner._prepare_sync(context_id=ident, identity='bob')['ok']
    runner._store_browser_cookies(ident, 'alice', [
        {'name':'SHOPSESSID', 'value':'alice', 'domain':'lab30', 'path':'/', 'expires':-1, 'httpOnly':True},
        {'name':'role', 'value':'admin', 'domain':'evil.test', 'path':'/'},
    ])
    checked = runner._prepare_sync(context_id=ident, identity='alice')
    assert checked['ok'], checked
    cookie = list(runner._contexts[ident]['sessions']['alice']['client'].cookies.jar)[0]
    assert cookie.domain == 'lab30.local'
    assert cookie.domain_specified is False
    assert runner._prepare_sync(context_id=ident, identity='bob')['ok']
    runner._store_browser_cookies(ident, 'alice', [])  # a real logout deletes the cookie
    assert not runner._prepare_sync(context_id=ident, identity='alice')['ok']
    assert runner._prepare_sync(context_id=ident, identity='bob')['ok']


@pytest.mark.parametrize('kind,endpoint', [('http', '/v1/http'), ('browser', '/v1/browser/check')])
def test_observations_share_host_id_and_are_queryable_while_running(isolated, monkeypatch, kind, endpoint):
    started, finish = threading.Event(), threading.Event()
    executions = []

    def execute(request):
        executions.append(request.job_id)
        started.set()
        assert finish.wait(5)
        return {'status': 302, 'body': 'observed-body', 'headers': {'location': '/account/'}} if kind == 'http' else {
            'available': True, 'dialogs': ['observed-dialog'], 'body_text': 'observed-body', 'evaluated': 'observed-value'}

    monkeypatch.setattr(runner, '_observe_sync' if kind == 'http' else '_browser_sync', execute)
    headers = {'Authorization': 'Bearer test-token'}
    with TestClient(runner.app) as client:
        ident = client.post('/v1/verification-contexts', headers=headers, json={'run_id': 'r', 'finding_id': 'f'}).json()['context_id']
        payload = {'job_id': 'stable-observation', 'context_id': ident, 'identity': 'alice', 'path': '/'}
        replies = []
        thread = threading.Thread(target=lambda: replies.append(client.post(endpoint, headers=headers, json=payload)))
        thread.start()
        assert started.wait(5)
        active = client.get('/v1/jobs/stable-observation', headers=headers).json()
        assert active['kind'] == kind and active['status'] == 'running'
        assert active['context_id'] == ident and active['identity'] == 'alice'
        replay = client.post(endpoint, headers=headers, json=payload)
        assert replay.json()['status'] == 'running'
        changed = client.post(endpoint, headers=headers, json={**payload, 'path': '/account/me.php'})
        assert changed.status_code == 409
        other_identity = client.post(endpoint, headers=headers, json={**payload, 'identity': 'bob'})
        assert other_identity.status_code == 409
        # Same id cannot collide across endpoints, even with the same identity.
        collision = client.post('/v1/jobs', headers=headers, json={
            'job_id': 'stable-observation', 'context_id': ident, 'language': 'python', 'script': 'print(1)'})
        assert collision.status_code == 409
        assert executions == ['stable-observation']
        finish.set()
        thread.join(5)
        assert replies[0].status_code == 200
        final = client.get('/v1/jobs/stable-observation', headers=headers).json()
        assert final['status'] == 'finished' and final['exit_code'] == 0
        assert final['precondition']['ok'] is True
        if kind == 'http':
            assert final['http_status'] == 302 and final['body'] == 'observed-body'
            assert final['headers'] == {'location': '/account/'}
        else:
            assert final['dialogs'] == ['observed-dialog'] and final['evaluated'] == 'observed-value'
        same = client.post(endpoint, headers=headers, json=payload)
        assert same.json() == replies[0].json(), 'a completed id must return its original response'
        assert executions == ['stable-observation']
        client.delete('/v1/verification-contexts/' + ident, headers=headers)
        second = client.post('/v1/verification-contexts', headers=headers, json={'run_id': 'r2', 'finding_id': 'f2'}).json()['context_id']
        other_context = client.post(endpoint, headers=headers, json={**payload, 'context_id': second})
        assert other_context.status_code == 409
        assert executions == ['stable-observation']


@pytest.mark.parametrize('kind,endpoint', [('http', '/v1/http'), ('browser', '/v1/browser/check')])
def test_failed_observation_is_retained_and_never_reexecuted(isolated, monkeypatch, kind, endpoint):
    executions = []
    def failed(request):
        executions.append(request.job_id)
        raise ValueError('controlled-failure')
    monkeypatch.setattr(runner, '_observe_sync' if kind == 'http' else '_browser_sync', failed)
    headers = {'Authorization': 'Bearer test-token'}
    with TestClient(runner.app) as client:
        ident = client.post('/v1/verification-contexts', headers=headers, json={'run_id': 'r', 'finding_id': 'f'}).json()['context_id']
        payload = {'job_id': 'failed-observation', 'context_id': ident, 'path': '/'}
        first = client.post(endpoint, headers=headers, json=payload).json()
        repeated = client.post(endpoint, headers=headers, json=payload).json()
        assert first == repeated and first['error'] == 'ValueError'
        job = client.get('/v1/jobs/failed-observation', headers=headers).json()
        assert job['status'] == 'error' and job['exit_code'] is None
        assert job['context_id'] == ident and job['precondition']['ok'] is True
        assert executions == ['failed-observation']


def test_health_advertises_all_idempotency_and_identity_capabilities(isolated):
    capabilities = runner.healthz()['capabilities']
    assert all(capabilities[name] is True for name in (
        'verification_contexts', 'identity_preconditions', 'idempotent_jobs',
        'idempotent_http_jobs', 'idempotent_browser_jobs'))


def test_host_client_and_runner_use_the_same_job_identity_and_budget(isolated, monkeypatch):
    from audit.poc_agent import PocDeps
    from audit.poc_runner import PocRunnerClient
    from audit.runtime import AgentPolicy, Execution

    monkeypatch.setattr(runner, '_execute', lambda request: {
        'job_id': request.job_id, 'status': 'finished', 'exit_code': 0, 'stdout': 'normal attack'})
    monkeypatch.setattr(runner, '_browser_sync', lambda request: {
        'available': True, 'dialogs': ['attack'], 'body_text': 'normal'})
    async def scenario():
        client = PocRunnerClient('http://runner', 'test-token', transport=httpx.ASGITransport(app=runner.app))
        try:
            created = await client.create_context(run_id='r', finding_id='f')
            data = PocDeps(client=client, policy={}, target='lab30', finding={'id': 'f'},
                           context_id=created['context_id'], max_jobs=3)
            data.execution = Execution({'responses': 4, 'tools': 8, 'seconds': 30}, AgentPolicy(), lambda _: None)
            data.execution.enter('poc_execute')
            first = json.loads(await data.call('http_observe', {'path': '/'}))
            second = json.loads(await data.call('browser_check', {'path': '/'}))
            third = json.loads(await data.call('run_poc', {'language': 'python', 'script': 'print(1)'}))
            assert first['status'] == 200 and first['execution_status'] == 'finished'
            assert second['dialogs'] == ['attack'] and second['exit_code'] == 0
            assert third['stdout'] == 'normal attack' and third['exit_code'] == 0
            assert len({record['job_id'] for record in data.jobs}) == 3
            for record in data.jobs:
                stored = await client.get_job(record['job_id'])
                assert stored['job_id'] == record['job_id']
                assert stored['context_id'] == data.context_id
                assert stored['status'] == 'finished'
            refused = json.loads(await data.call('http_observe', {'path': '/'}))
            assert refused['error'] == 'job_limit' and len(runner._jobs) == 3
            await client.close_context(data.context_id)
        finally:
            await client.aclose()
    asyncio.run(scenario())


@pytest.mark.parametrize('metadata', [
    {'status': 'failed'}, {'exit_code': 1}, {'timed_out': True}, {'available': False},
])
def test_browser_registration_does_not_promote_failed_execution_to_success(isolated, metadata):
    result, job = runner._observation_job({'job_id': 'failed', 'available': True, **metadata}, 'browser')
    assert result['execution_status'] != 'finished'
    assert result['exit_code'] != 0
    assert job['status'] != 'finished'


def test_closing_context_waits_for_accepted_job_queued_before_execution(isolated, monkeypatch):
    async def scenario():
        semaphore = asyncio.Semaphore(0)
        monkeypatch.setattr(runner, '_semaphore', semaphore)
        executed = []
        monkeypatch.setattr(runner, '_observe_sync', lambda _: executed.append(True))
        ident = context()
        pending = asyncio.create_task(runner.http_observe(runner.HttpRequest(
            context_id=ident, path='/', job_id='queued-job')))
        for _ in range(20):
            if 'queued-job' in runner._jobs:
                break
            await asyncio.sleep(0)
        assert runner._contexts[ident]['active'] == 0
        assert runner._contexts[ident]['pending_jobs'] == 1
        assert runner.close_context(ident)['state'] == 'closing'
        with pytest.raises(HTTPException):
            context('next-finding')
        semaphore.release()
        result = await asyncio.wait_for(pending, 2)
        assert result['execution_status'] == 'error'
        assert not executed, 'closing contexts cannot execute a queued side effect'
        assert runner._contexts[ident]['pending_jobs'] == 0
        assert runner._contexts[ident]['state'] == 'closed'
        assert runner._jobs['queued-job']['status'] == 'error'
        context('next-finding')
    asyncio.run(scenario())
