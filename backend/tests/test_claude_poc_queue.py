"""Interactive SDK queue contracts; no actual SDK, provider or runner is used."""
import asyncio
import copy
import json
from types import SimpleNamespace

import pytest

from audit.poc import PocPolicy
from audit.poc import PocVerifier
from audit.runtimes.claude_poc import MemoryPocRequestGateway
from audit.runtimes.claude_queue import ClaudeQueuePocRuntime, QUEUE_POLICY
from audit.runtime import StopAudit
from tests.test_claude_poc_runtime import FakeSDK, ResultMessage, http_job, limits, service
from tests.test_poc_agent import settings, FakeBus, FakeClient, CONFIG
from tests.test_poc_store import state, record  # noqa: F401


class InteractiveSDK(FakeSDK):
    def __init__(self, handlers):
        super().__init__([])
        self.handlers = list(handlers)
        self.clients = []
        self.owner = None
        self.interrupts = 0
        self.interrupted = asyncio.Event()

    def ClaudeSDKClient(self, *, options):
        sdk = self

        class Client:
            async def __aenter__(self):
                sdk.owner = asyncio.current_task()
                sdk.clients.append(self)
                self.options = options
                return self

            async def __aexit__(self, *args):
                assert asyncio.current_task() is sdk.owner
                self.closed = True

            async def query(self, prompt):
                assert asyncio.current_task() is sdk.owner
                sdk.interrupted.clear()
                sdk.calls.append(dict(prompt=prompt, options=options))
                self.handler = sdk.handlers.pop(0)

            async def interrupt(self):
                sdk.interrupts += 1
                sdk.interrupted.set()

            async def receive_response(self):
                assert asyncio.current_task() is sdk.owner
                async for message in self.handler():
                    yield message

        return Client()


def runtime(tmp_path, handlers, **kwargs):
    sdk = InteractiveSDK(handlers)
    rt = ClaudeQueuePocRuntime(limits=limits(tmp_path, **kwargs), gateway=MemoryPocRequestGateway(),
        sdk=sdk, cli_probe=lambda: ('2.1.310', ''), tasks=[
            dict(finding_id='finding-1', state='pending'), dict(finding_id='finding-2', state='pending')])
    return rt, sdk


def payload(deps, *, status='inconclusive', **kwargs):
    return {**dict(finding_id=deps.finding['id'], revision=deps.finding.get('revision', 1),
                context_id=deps.context_id, status=status, summary='离线观测'), **kwargs}


async def invoke(rt, deps, events, saved):
    def publisher(result, usage):
        saved.append(dict(finding_id=deps.finding['id'], result=result, usage=copy.deepcopy(usage)))
        return dict(id=f'v-{len(saved)}')
    return await rt.verify(service=deps, emit=events.append, run_id='run-1', epoch=1, publisher=publisher)


def test_one_client_consumes_two_items_and_publishes_before_result_message(tmp_path):
    events, saved = [], []
    first = service(tmp_path)
    second = service(tmp_path, context_id='ctx-2')
    second.finding = {**second.finding, 'id': 'finding-2'}

    async def response():
        deps = rt._service
        tasks = json.loads(await rt.call_tool('get_verification_tasks', {}))['items']
        assert next(item for item in tasks if item['finding_id'] == deps.finding['id'])['state'] == 'running'
        if deps is second:
            assert tasks[0]['state'] == 'completed'
        answer = json.loads(await rt.call_tool('publish_verification', payload(deps)))
        assert answer['ok']
        assert saved[-1]['finding_id'] == deps.finding['id']
        assert saved[-1]['usage']['usage_status'] == 'awaiting_sdk_result'
        assert json.loads(await rt.call_tool('run_poc', {}))['error'] == 'tools_withdrawn'
        yield ResultMessage(usage=dict(input_tokens=10, output_tokens=2), cost=.01 if len(saved) == 1 else .025)

    rt, sdk = runtime(tmp_path, [response, response], max_seconds=60)

    async def scenario():
        try:
            a = await invoke(rt, first, events, saved)
            b = await invoke(rt, second, events, saved)
            return a, b
        finally:
            await rt.aclose()

    a, b = asyncio.run(scenario())
    assert a.result.status == b.result.status == 'inconclusive'
    assert len(sdk.clients) == 1 and sdk.clients[0].closed
    assert len(sdk.calls) == 2  # no second conclude process/query
    assert sdk.calls[0]['options'] is sdk.calls[1]['options']
    assert sdk.calls[0]['options'].max_turns is None
    assert sdk.calls[0]['options'].include_partial_messages is True
    assert b.usage['usage']['input_tokens'] == 10  # per-response, not duplicate cumulative usage
    assert a.usage['usage']['cost_usd'] == .01
    assert b.usage['usage']['cost_usd'] == .015
    assert a.usage['usage_status'] == b.usage['usage_status'] == 'final'
    assert a.usage['runtime']['time_policy'] == 'run-budget'
    assert a.usage['runtime']['max_turns'] is None
    assert 'conclude_requests' not in a.usage['runtime']
    assert len([e for e in events if e['kind'] == 'poc_runtime_usage']) == 2
    assert not any(e['kind'] in {'model_request', 'model_response'} for e in events)


def test_current_evidence_ids_support_http_but_foreign_context_and_version_do_not(tmp_path):
    events, saved = [], []
    jobs = [http_job('normal', body='NORMAL'), http_job('attack', body='ATTACK')]
    first = service(tmp_path, jobs=jobs)
    second = service(tmp_path, jobs=jobs, context_id='ctx-2')  # deliberately foreign jobs
    second.finding = {**second.finding, 'id': 'finding-2', 'revision': 2}
    old_refs = []

    async def response_one():
        view = json.loads(await rt.call_tool('get_verification_evidence', {}))
        by_job = {r['job_id']: r['evidence_ref_id'] for r in view['evidence'] if r['channel'] == 'body'}
        old_refs.extend(by_job.values())
        data = payload(first, status='verified', normal_observation='NORMAL', attack_observation='ATTACK',
                       normal_refs=[by_job['normal']], attack_refs=[by_job['attack']])
        assert json.loads(await rt.call_tool('publish_verification', data))['ok']
        # Replaying the same publication is idempotent; a changed verdict is not.
        assert json.loads(await rt.call_tool('publish_verification', data))['already_published']
        assert not json.loads(await rt.call_tool('publish_verification', {**data, 'status': 'rejected'}))['ok']
        yield ResultMessage()

    async def response_two():
        view = json.loads(await rt.call_tool('get_verification_evidence', {}))
        assert view['evidence'] == []
        assert not json.loads(await rt.call_tool('publish_verification', payload(second, revision=1)))['ok']
        data = payload(second, status='verified', normal_observation='N', attack_observation='A',
                       normal_refs=old_refs[:1], attack_refs=old_refs[1:])
        assert not json.loads(await rt.call_tool('publish_verification', data))['ok']
        assert json.loads(await rt.call_tool('publish_verification', payload(second)))['ok']
        yield ResultMessage()

    rt, _ = runtime(tmp_path, [response_one, response_two])

    async def scenario():
        try:
            a = await invoke(rt, first, events, saved)
            b = await invoke(rt, second, events, saved)
            return a, b
        finally:
            await rt.aclose()

    a, b = asyncio.run(scenario())
    assert a.result.status == 'verified'
    assert b.result.status == 'inconclusive'
    assert len(saved) == 2
    assert a.result.normal_evidence[0].job_id == 'normal'


@pytest.mark.parametrize('fault', ['sdk_error', 'cancel', 'deadline'])
def test_mid_queue_stop_preserves_committed_items_and_never_replays(tmp_path, fault):
    events, saved = [], []
    first, second = service(tmp_path), service(tmp_path, context_id='ctx-2')
    second.finding['id'] = 'finding-2'
    stopped = False
    second.should_stop = lambda: stopped

    async def good():
        assert json.loads(await rt.call_tool('publish_verification', payload(first)))['ok']
        yield ResultMessage()

    async def bad():
        nonlocal stopped
        if fault == 'sdk_error':
            yield ResultMessage(is_error=True, subtype='error_during_execution')
        else:
            stopped = fault == 'cancel'
            if fault == 'deadline':
                rt._attempt_deadline = __import__('time').monotonic() + .015
            await asyncio.Event().wait()
            yield ResultMessage()

    rt, sdk = runtime(tmp_path, [good, bad])
    rt.HEARTBEAT_SECONDS = .01

    async def scenario():
        try:
            a = await invoke(rt, first, events, saved)
            if fault == 'sdk_error':
                b = await invoke(rt, second, events, saved)
                assert b.result is None and b.reason == 'sdk_api_error'
            else:
                with pytest.raises(StopAudit):
                    await invoke(rt, second, events, saved)
            return a
        finally:
            await rt.aclose()

    a = asyncio.run(scenario())
    assert a.result.status == 'inconclusive' and len(saved) == 1
    assert len(sdk.clients) == 1 and len(sdk.calls) == 2
    assert sdk.clients[0].closed


def test_elapsed_warning_keeps_the_session_alive_and_streams_metadata_only(tmp_path):
    events, saved = [], []
    deps = service(tmp_path)
    deps.policy.update(item_warning_seconds=.001)

    async def response():
        await asyncio.sleep(.035)
        yield SimpleNamespace(event=dict(delta=dict(type='thinking_delta', thinking='PRIVATE_REASONING')))
        yield SimpleNamespace(event=dict(delta=dict(type='text_delta', text='SECRET_PUBLIC_TEXT')))
        assert json.loads(await rt.call_tool('publish_verification', payload(deps)))['ok']
        yield ResultMessage()

    rt, _ = runtime(tmp_path, [response], max_seconds=60)
    rt.HEARTBEAT_SECONDS = .01

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    result = asyncio.run(scenario())
    assert result.reason == 'completed'
    assert any(e['kind'] == 'poc_queue_heartbeat' and e['soft_limit_exceeded'] for e in events)
    assert any(e['kind'] == 'poc_queue_progress' for e in events)
    assert 'PRIVATE_REASONING' not in json.dumps(events)
    assert 'SECRET_PUBLIC_TEXT' not in json.dumps(events)


def test_missing_publication_gets_bounded_readonly_corrections_in_same_session(tmp_path):
    events, saved = [], []
    deps = service(tmp_path)

    async def no_publication():
        yield ResultMessage()

    async def correction():
        assert json.loads(await rt.call_tool('http_observe', {}))['error'] == 'tools_withdrawn'
        assert json.loads(await rt.call_tool('publish_verification', payload(deps)))['ok']
        yield ResultMessage()

    rt, sdk = runtime(tmp_path, [no_publication, correction])

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    assert asyncio.run(scenario()).result.status == 'inconclusive'
    assert len(sdk.clients) == 1 and len(sdk.calls) == 2 and len(saved) == 1


def test_host_ends_post_publication_narration_and_continues_same_client(tmp_path):
    events, saved = [], []
    a, b = service(tmp_path), service(tmp_path, context_id='ctx-2')
    b.finding['id'] = 'finding-2'

    async def publish_then_wait():
        assert json.loads(await rt.call_tool('publish_verification', payload(rt._service)))['ok']
        await sdk.interrupted.wait()
        final = ResultMessage(is_error=True)
        final.terminal_reason = 'aborted_streaming'
        yield final

    rt, sdk = runtime(tmp_path, [publish_then_wait, publish_then_wait])
    rt.HEARTBEAT_SECONDS = .01

    async def scenario():
        try:
            first = await invoke(rt, a, events, saved)
            second = await invoke(rt, b, events, saved)
            return first, second
        finally:
            await rt.aclose()

    first, second = asyncio.run(scenario())
    assert first.reason == second.reason == 'completed'
    assert len(saved) == 2 and sdk.interrupts == 2
    assert len(sdk.clients) == 1 and not rt._query_failed


def test_real_sdk_interactive_transport_reuses_mcp_and_publishes_each_item_offline(tmp_path):
    sdk = pytest.importorskip('claude_agent_sdk')
    events, saved = [], []
    a, b = service(tmp_path), service(tmp_path, context_id='ctx-2')
    b.finding['id'] = 'finding-2'

    class Transport(sdk.Transport):
        def __init__(self):
            self.queue = asyncio.Queue()
            self.connections = self.turns = self.publications = 0
            self.closed = False

        async def connect(self):
            self.connections += 1

        async def write(self, raw):
            message = json.loads(raw)
            if message['type'] == 'control_request':
                assert message['request']['subtype'] == 'initialize'
                await self.queue.put(dict(type='control_response', response=dict(subtype='success',
                    request_id=message['request_id'], response={})))
            elif message['type'] == 'user':
                self.turns += 1
                if self.turns == 1:
                    await self.mcp('init', dict(jsonrpc='2.0', id=0, method='initialize', params=dict(
                        protocolVersion='2025-03-26', capabilities={}, clientInfo=dict(name='offline-queue', version='1'))))
                else:
                    await self.publish()
            elif message['type'] == 'control_response':
                rid = message['response']['request_id']
                if rid == 'init':
                    await self.mcp('ready', dict(jsonrpc='2.0', method='notifications/initialized'))
                elif rid == 'ready':
                    await self.publish()
                else:
                    reply = message['response']['response']['mcp_response']['result']['content'][0]['text']
                    assert json.loads(reply)['ok']
                    assert len(saved) == self.turns  # publication precedes result
                    self.publications += 1
                    await self.queue.put(dict(type='result', subtype='success', is_error=False,
                        duration_ms=1, duration_api_ms=1, num_turns=1, session_id='offline-session',
                        terminal_reason='completed', usage=dict(input_tokens=7, output_tokens=3),
                        total_cost_usd=self.turns * .01))

        async def mcp(self, request_id, message):
            await self.queue.put(dict(type='control_request', request_id=request_id,
                request=dict(subtype='mcp_message', server_name='poc', message=message)))

        async def publish(self):
            await self.mcp(f'publish-{self.turns}', dict(jsonrpc='2.0', id=self.turns + 1,
                method='tools/call', params=dict(name='publish_verification', arguments=payload(rt._service))))

        async def read_messages(self):
            while (message := await self.queue.get()) is not None:
                yield message

        async def close(self):
            self.closed = True
            await self.queue.put(None)

        async def end_input(self):
            pass

        def is_ready(self):
            return not self.closed

    async def scenario():
        nonlocal rt
        transport = Transport()
        proxy = SimpleNamespace(ClaudeAgentOptions=sdk.ClaudeAgentOptions, tool=sdk.tool,
            create_sdk_mcp_server=sdk.create_sdk_mcp_server,
            ClaudeSDKClient=lambda **kwargs: sdk.ClaudeSDKClient(**kwargs, transport=transport))
        rt = ClaudeQueuePocRuntime(limits=limits(tmp_path), gateway=MemoryPocRequestGateway(),
            sdk=proxy, cli_probe=lambda: ('2.1.310', ''))
        try:
            first = await invoke(rt, a, events, saved)
            second = await invoke(rt, b, events, saved)
            return transport, first, second
        finally:
            await rt.aclose()

    rt = None
    transport, first, second = asyncio.run(scenario())
    assert transport.connections == 1 and transport.turns == transport.publications == 2
    assert transport.closed and len(saved) == 2
    assert first.result.status == second.result.status == 'inconclusive'
    assert first.usage['usage']['input_tokens'] == second.usage['usage']['input_tokens'] == 7
    assert first.usage['usage']['cost_usd'] == second.usage['usage']['cost_usd'] == .01


def test_old_runs_do_not_adopt_the_queue_implicitly(tmp_path):
    config = settings(tmp_path)
    from dataclasses import replace
    config.poc = replace(config.poc, runtime='claude_sdk')
    old = dict(poc_mode='auto', poc_policy=dict(runtime='claude_sdk'))
    assert not PocPolicy.from_run(old, config).queued
    assert PocPolicy.from_run({**old, 'poc_policy': dict(runtime='claude_sdk', session_policy=QUEUE_POLICY)}, config).queued


@pytest.mark.parametrize('invalid', ['failed', 'timeout', 'http_xss', 'missing_control'])
def test_evidence_gates_are_unchanged_in_tool_publication(tmp_path, invalid):
    events, saved = [], []
    fact = http_job()
    if invalid == 'failed':
        fact['precondition']['ok'] = False
    if invalid == 'timeout':
        fact['result']['timed_out'] = True
    deps = service(tmp_path, jobs=[fact])
    if invalid == 'http_xss':
        deps.finding['vulnerability_type'] = 'xss_r'

    async def response():
        refs = json.loads(await rt.call_tool('get_verification_evidence', {}))['evidence']
        data = payload(deps, status='verified', normal_observation='正常', attack_observation='攻击',
                       normal_refs=[] if invalid == 'missing_control' else [r['evidence_ref_id'] for r in refs[:1]],
                       attack_refs=[r['evidence_ref_id'] for r in refs[:1]], jobs=['job-1'])
        assert not json.loads(await rt.call_tool('publish_verification', data))['ok']
        assert json.loads(await rt.call_tool('publish_verification', payload(deps)))['ok']
        yield ResultMessage()

    rt, _ = runtime(tmp_path, [response])

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    assert asyncio.run(scenario()).result.status == 'inconclusive'
    assert len(saved) == 1 and saved[0]['result'].status == 'inconclusive'


def test_verifier_commits_from_the_tool_once_and_finalizes_actual_result_usage(state, tmp_path):
    store, run, finding = state
    claim = store.claim_poc_attempt(run['id'], finding, 'target', run['execution_epoch'])
    store.start_poc_attempt(claim['key'], run['execution_epoch'])
    verifier = PocVerifier(store=store, bus=FakeBus(), settings=settings(tmp_path), client_factory=FakeClient)

    async def response():
        binding = rt._binding()
        assert json.loads(await rt.call_tool('publish_verification', dict(**binding,
            status='inconclusive', summary='对照尚不足，保留原事实')))['ok']
        # The durable record exists while the SDK is still streaming.
        records = store.list_verifications(finding['id'])
        assert len(records) == 1 and records[0]['agent']['usage']['usage_status'] == 'awaiting_sdk_result'
        yield ResultMessage(usage=dict(input_tokens=77, output_tokens=11))

    rt, sdk = runtime(tmp_path, [response])
    policy = PocPolicy(mode='auto', enabled=True, runtime='claude_sdk', session_policy=QUEUE_POLICY)

    async def scenario():
        try:
            return await verifier._verify_with_context(run, finding, policy, dict(identity='alice'), FakeClient(),
                model_config=CONFIG, attempt_key=claim['key'], target_key='target', context_id='ctx-1', queue_runtime=rt)
        finally:
            await rt.aclose()

    result, reason, recorded, _, _ = asyncio.run(scenario())
    assert result.status == 'inconclusive' and reason == 'completed'
    records = store.list_verifications(finding['id'])
    assert len(records) == 1 and records[0]['id'] == recorded['id']
    assert records[0]['agent']['usage']['usage_status'] == 'final'
    assert records[0]['agent']['usage']['usage']['input_tokens'] == 77
    assert len(sdk.clients) == 1


def test_queue_runtime_uses_remaining_run_budget_instead_of_old_item_limits(state, tmp_path, monkeypatch):
    store, run, finding = state
    store._write('UPDATE run_execution_state SET limits=? WHERE run_id=?',
                 (json.dumps(dict(responses=90, tools=100, seconds=1800)), run['id']))
    from audit.runtimes.claude_poc import ClaudePocLimits
    monkeypatch.setattr(ClaudePocLimits, 'from_environ', classmethod(lambda cls: limits(tmp_path,
        max_seconds=30, execute_requests=2)))
    verifier = PocVerifier(store=store, bus=FakeBus(), settings=settings(tmp_path), client_factory=FakeClient)
    rt = verifier._make_queue_runtime(run, [(finding, finding['id'], 1)])
    assert rt.limits.max_seconds > 1700
    assert rt.limits.execute_requests == 90
    assert len(rt._tasks) == 1


def test_final_usage_updates_metadata_only_and_is_epoch_guarded(state):
    store, run, finding = state
    claim = store.claim_poc_attempt(run['id'], finding, 'target', run['execution_epoch'])
    store.start_poc_attempt(claim['key'], run['execution_epoch'])
    data = record(finding)
    assert store.record_automatic_verification_guarded(data, attempt_key=claim['key'], epoch=run['execution_epoch'])
    before = store.list_verifications(finding['id'])[0]
    usage = dict(usage_status='final', usage=dict(input_tokens=10))
    assert not store.finalize_poc_verification_usage(run['id'], data['id'], usage, run['execution_epoch'] + 1)
    assert store.finalize_poc_verification_usage(run['id'], data['id'], usage, run['execution_epoch'])
    after = store.list_verifications(finding['id'])[0]
    assert after['status'] == before['status'] and after['verdict'] == before['verdict']
    assert after['agent']['usage'] == usage


def test_queue_view_recovers_claims_without_replaying_jobs_or_changing_old_runs(state):
    store, run, finding = state
    assert store.poc_queue_view(run['id']) is None
    store._write("UPDATE runs SET poc_policy=? WHERE id=?", (json.dumps(dict(session_policy=QUEUE_POLICY)), run['id']))
    view = store.execution_summary(run['id'])['poc_queue']
    assert view['total'] == 1 and view['counts'] == dict(pending=1)
    claim = store.claim_poc_attempt(run['id'], finding, 'target', run['execution_epoch'])
    store.start_poc_attempt(claim['key'], run['execution_epoch'])
    store.note_poc_job(claim['key'], 'original-job', run['execution_epoch'])
    assert store.execution_summary(run['id'])['poc_queue']['counts'] == dict(running=1)
    store.interrupt_poc_attempts(run['id'], epoch=run['execution_epoch'])
    view = store.execution_summary(run['id'])['poc_queue']
    assert view['counts'] == dict(interrupted=1) and view['items'][0]['job_id'] == 'original-job'
    assert not store.claim_poc_attempt(run['id'], finding, 'target', run['execution_epoch'])['claimed']


# --- bounded-evidence progress: checkpoints, continuation, recovery -------------------


def progress_service(tmp_path, *, context_id='ctx-1', **params):
    """A service under the frozen bounded-evidence policy, with a working runner fake."""
    from audit.poc_source import PROGRESS_POLICY, progress_policy_snapshot
    deps = service(tmp_path, context_id=context_id)
    deps.client = FakeClient()
    deps.policy.update(progress_policy=PROGRESS_POLICY,
                       progress_params={**progress_policy_snapshot(), **params})
    return deps


def continuation(checkpoint_id, **overrides):
    values = dict(checkpoint_id=checkpoint_id, hypothesis='账号字段可能被直接绑定到角色列',
                  basis='已有响应的正文回显了当前会话的角色字段',
                  next_experiment='用同一路径提交 role=admin 并观察响应',
                  expected_result='攻击响应显示管理员角色而正常响应不显示')
    values.update(overrides)
    return values


def test_duplicate_experiments_take_checkpoints_and_only_a_declared_batch_reopens(tmp_path):
    events, saved, bound = [], [], {}

    async def response():
        bound['deadline'] = rt._queue_deadline
        first = json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php'}))
        assert first['job_id'] and 'checkpoint' not in first
        duplicate = json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php'}))
        assert duplicate['ok'] is False and duplicate['error'] == 'duplicate_experiment'
        assert duplicate['duplicate_of'] == first['job_id']
        checkpoint = duplicate['checkpoint']
        assert checkpoint['checkpoint_id'] == 'cp-1'
        assert checkpoint['reason'] == 'duplicate_experiment'
        assert checkpoint['completed_experiments'] == 1
        assert checkpoint['job_ids'] == [first['job_id']]
        assert checkpoint['interpretation'] == {
            'provided': False, 'note': '宿主只登记实际作业与原文；解释与角色划分须由你引用证据后给出。'}
        assert checkpoint['next_action'] == 'continue_verification'
        blocked = json.loads(await rt.call_tool('http_observe', {'path': '/account/update.php'}))
        assert blocked['error'] == 'checkpoint_readonly'
        # Stale and unknown ids cannot unlock anything.
        assert json.loads(await rt.call_tool('continue_verification',
                                             continuation('cp-9')))['error'] == 'unknown_checkpoint'
        opened = json.loads(await rt.call_tool('continue_verification', continuation('cp-1')))
        assert opened['ok'] and opened['continues_remaining'] == 1 and opened['experiments'] == 2
        second = json.loads(await rt.call_tool('http_observe', {'path': '/account/update.php'}))
        assert second['job_id'] and 'checkpoint' not in second
        # The granted batch is bounded: its second job ends the batch with a checkpoint.
        retry = json.loads(await rt.call_tool('http_observe', {'path': '/account/update.php'}))
        assert retry['job_id'] and retry['checkpoint']['checkpoint_id'] == 'cp-2'
        assert json.loads(await rt.call_tool('publish_verification', payload(deps)))['ok']
        yield ResultMessage()

    rt, sdk = runtime(tmp_path, [response])
    deps = progress_service(tmp_path)

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    outcome = asyncio.run(scenario())
    assert outcome.reason == 'completed'
    assert [e['kind'] for e in events].count('poc_queue_checkpoint') == 2
    assert [e['kind'] for e in events].count('poc_queue_continued') == 1
    refused = [e for e in events if e['kind'] == 'poc_queue_experiment_refused']
    assert len(refused) == 1 and refused[0]['reason'] == 'duplicate_experiment'
    assert 'mcp__poc__continue_verification' in sdk.calls[0]['options'].allowed_tools
    assert 'continue_verification' in sdk.tools
    usage = saved[-1]['usage']
    assert usage['progress']['policy'] == 'bounded-evidence-v1'
    # The conclusion is saved while the item is still in its read-only checkpoint.
    assert usage['progress']['state'] == 'checkpoint'
    assert usage['progress']['experiments'] == 3
    assert usage['progress']['counts']['jobs'] == 3
    assert len(usage['progress']['checkpoints']) == 2
    assert usage['progress']['continues'][0]['checkpoint_id'] == 'cp-1'
    assert usage['progress']['recovery'] == {}
    # A checkpoint and a continuation never extend the item's own queue window.
    assert rt._queue_deadline == bound['deadline']
    assert rt._experiment_deadline <= bound['deadline']


def test_same_path_under_another_identity_or_a_different_script_is_not_a_duplicate(tmp_path):
    events, saved = [], []
    deps = progress_service(tmp_path)

    async def response():
        a = json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php', 'identity': 'alice'}))
        assert a['job_id'] and 'checkpoint' not in a
        b = json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php', 'identity': 'bob'}))
        # A different identity is a different experiment; the second job merely
        # completes the batch, so the checkpoint reason is the count, not a duplicate.
        assert b['job_id'] and b['checkpoint']['reason'] == 'experiments'
        assert b['checkpoint']['completed_experiments'] == 2
        assert json.loads(await rt.call_tool('publish_verification', payload(deps)))['ok']
        yield ResultMessage()

    rt, _ = runtime(tmp_path, [response])

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    assert asyncio.run(scenario()).reason == 'completed'
    assert len([e for e in events if e['kind'] == 'poc_queue_experiment_refused']) == 0
    assert len(deps.jobs) == 2
    assert {job['identity'] for job in deps.jobs} == {'alice', 'bob'}


def test_a_checkpoint_cannot_unlock_a_rebound_item(tmp_path):
    events, saved = [], []
    deps = progress_service(tmp_path)

    async def response():
        assert json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php'}))['job_id']
        duplicate = json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php'}))
        assert duplicate['checkpoint']['checkpoint_id'] == 'cp-1'
        deps.finding['project_revision'] = 2
        rebound = json.loads(await rt.call_tool('continue_verification', continuation('cp-1')))
        assert rebound['error'] == 'binding_changed'
        deps.finding['project_revision'] = 1
        assert json.loads(await rt.call_tool('publish_verification', payload(deps)))['ok']
        yield ResultMessage()

    rt, _ = runtime(tmp_path, [response])

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    assert asyncio.run(scenario()).reason == 'completed'
    assert [e['kind'] for e in events].count('poc_queue_continued') == 0


def test_stream_break_keeps_jobs_and_recovers_read_only_without_experiments(tmp_path):
    events, saved = [], []
    deps = progress_service(tmp_path)

    async def broken():
        assert json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php'}))['job_id']
        # A long, continuously streaming response that then loses its transport: the
        # host must keep the job and the observations, not discard the item.
        for _ in range(2109):
            yield SimpleNamespace(event=dict(delta=dict(type='text_delta', text='STREAM_TEXT')))
        raise ConnectionError('upstream reset')

    rt, sdk = runtime(tmp_path, [broken])
    # The recovery is a fresh conclusion-only stage: no MCP server and no tool list.
    sdk.script = [lambda options: [ResultMessage(dict(
        status='inconclusive', summary='已完成的作业只支持部分结论。'))]]

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    outcome = asyncio.run(scenario())
    kinds = [e['kind'] for e in events]
    assert outcome.reason == 'completed' and outcome.result.status == 'inconclusive'
    assert outcome.usage['progress']['stream_error'] == 'stream_connection_error'
    assert outcome.usage['progress']['recovery']['published'] is True
    assert len(saved) == 1 and len(deps.jobs) == 1
    error = next(e for e in events if e['kind'] == 'poc_runtime_error')
    assert error['code'] == 'stream_connection_error' and error['events'] == 2109
    checkpoint = next(e for e in events if e['kind'] == 'poc_queue_checkpoint')
    assert checkpoint['reason'] == 'stream_error'
    assert checkpoint['job_ids'] == [deps.jobs[0]['job_id']]
    started = next(e for e in events if e['kind'] == 'poc_queue_recovery_started')
    assert started['requests'] == 3 and started['checkpoint_id'] == checkpoint['checkpoint_id']
    assert 'poc_queue_recovery_started' in kinds and 'poc_queue_recovery_published' in kinds
    conclude = sdk.calls[-1]['options']
    assert conclude.mcp_servers == {} and conclude.allowed_tools == []
    assert conclude.output_format['type'] == 'json_schema'
    assert 'STREAM_TEXT' not in json.dumps(events)


def test_recovery_requests_are_capped_by_both_progress_and_conclude_limits(tmp_path):
    """The recovery cannot borrow a larger conclusion allowance by asking for more."""
    events, saved = [], []
    deps = progress_service(tmp_path)

    async def broken():
        assert json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php'}))['job_id']
        raise ConnectionError('upstream reset')
        yield  # unreachable; keeps this handler an async generator like the SDK stream

    rt, sdk = runtime(tmp_path, [broken], conclude_requests=1)
    sdk.script = [lambda options: [ResultMessage(dict(
        status='inconclusive', summary='只允许一次只读回收请求。'))]]

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    outcome = asyncio.run(scenario())
    started = next(e for e in events if e['kind'] == 'poc_queue_recovery_started')
    assert started['requests'] == 1
    assert outcome.reason == 'completed' and len(saved) == 1
    assert rt.gateway.snapshot(run_id='run-1', epoch=1)['conclude']['limit'] == 1


def test_failed_recovery_keeps_the_item_undecided_and_never_invents_a_verdict(tmp_path):
    events, saved = [], []
    deps = progress_service(tmp_path)

    async def broken():
        assert json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php'}))['job_id']
        raise ConnectionError('upstream reset')
        yield  # unreachable; keeps this handler an async generator like the SDK stream

    rt, sdk = runtime(tmp_path, [broken])
    sdk.script = [lambda options: [ResultMessage(is_error=True, subtype='error_during_execution')]]

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    outcome = asyncio.run(scenario())
    assert outcome.result is None and outcome.reason == 'stream_connection_error'
    assert saved == [] and len(deps.jobs) == 1
    assert outcome.usage['progress']['recovery']['published'] is False
    assert 'poc_queue_recovery_failed' in [e['kind'] for e in events]


def test_a_publication_committed_before_the_break_is_never_overwritten(tmp_path):
    events, saved = [], []
    deps = progress_service(tmp_path)

    async def publish_then_break():
        assert json.loads(await rt.call_tool('publish_verification', payload(deps)))['ok']
        raise ConnectionError('upstream reset')
        yield  # unreachable; keeps this handler an async generator like the SDK stream

    rt, sdk = runtime(tmp_path, [publish_then_break])
    sdk.script = [lambda options: [ResultMessage(dict(status='verified', summary='不应被采用'))]]

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    outcome = asyncio.run(scenario())
    assert outcome.reason == 'completed' and outcome.result.status == 'inconclusive'
    assert len(saved) == 1 and saved[0]['result'].status == 'inconclusive'
    assert 'poc_queue_recovery_started' not in [e['kind'] for e in events]
    # Only the original execute query ran; the recovery never asked for a verdict.
    assert len(sdk.calls) == 1


@pytest.mark.parametrize('condition', ['unresolved_job', 'no_time'])
def test_recovery_does_not_start_without_a_confirmed_job_list_or_its_own_window(tmp_path, condition):
    events, saved = [], []
    deps = progress_service(tmp_path)

    async def broken():
        assert json.loads(await rt.call_tool('http_observe', {'path': '/account/me.php'}))['job_id']
        if condition == 'unresolved_job':
            deps.submission_unresolved = True
        else:
            rt._queue_deadline = __import__('time').monotonic() + 1
        raise ConnectionError('upstream reset')
        yield  # unreachable; keeps this handler an async generator like the SDK stream

    rt, sdk = runtime(tmp_path, [broken])
    sdk.script = [lambda options: [ResultMessage(dict(status='inconclusive', summary='不应被采用'))]]

    async def scenario():
        try:
            return await invoke(rt, deps, events, saved)
        finally:
            await rt.aclose()

    outcome = asyncio.run(scenario())
    assert outcome.result is None and outcome.reason == 'stream_connection_error'
    assert saved == []
    skipped = next(e for e in events if e['kind'] == 'poc_queue_recovery_skipped')
    assert skipped['reason'] == condition
    assert sdk.calls[-1]['options'].allowed_tools != []  # no conclude stage was opened
    assert outcome.usage['progress']['recovery']['attempted'] is False


def test_recorded_poc_runs_once_before_the_model_plans_the_item(tmp_path):
    """The audit's own POC is executed by the host; the model gets its transcript.

    Re-deriving a runnable check from source was the item's dominant wall-clock cost.
    The pre-run still goes through ``run_poc``: same identity, job limit and runner
    precondition; only the planning turn is removed.
    """
    events, saved = [], []
    service_ = service(tmp_path)
    from tests.test_poc_agent import FakeClient
    client = FakeClient()
    service_.client = client
    service_.policy = PocPolicy(runtime='claude_sdk', session_policy=QUEUE_POLICY).snapshot()
    script = "import os\nprint(os.environ['LAB30_URL'])\n"
    service_.finding = {**service_.finding,
                        'poc': {'filename': 'check.py', 'language': 'python', 'script': script}}

    async def response():
        # The job exists before the first model request, and its output is in the prompt.
        assert len(client.jobs) == 1 and client.jobs[0]['script'] == script
        assert '# 宿主已执行审计记录的 POC' in sdk.calls[0]['prompt']
        assert 'job-1' in sdk.calls[0]['prompt']
        assert json.loads(await rt.call_tool('publish_verification', payload(rt._service)))['ok']
        yield ResultMessage(usage=dict(input_tokens=10, output_tokens=2), cost=.01)

    rt, sdk = runtime(tmp_path, [response], max_seconds=60)

    async def scenario():
        try:
            return await invoke(rt, service_, events, saved)
        finally:
            await rt.aclose()

    outcome = asyncio.run(scenario())
    assert outcome.result.status == 'inconclusive'
    assert [event['kind'] for event in events if event['kind'].startswith('poc_stored_poc')] \
        == ['poc_stored_poc_executed']
    assert len(client.jobs) == 1


def test_a_checkpoint_continuation_does_not_rerun_the_recorded_poc(tmp_path):
    """One pre-run per finding: the continuation already has the transcript.

    Running the script twice would spend another job and repeat its side effects for
    evidence the model has already seen.
    """
    events, saved = [], []
    first = service(tmp_path)
    continued = service(tmp_path, context_id='ctx-continued')
    from tests.test_poc_agent import FakeClient
    client = FakeClient()
    script = "import os\nprint(os.environ['LAB30_URL'])\n"
    for deps in (first, continued):
        deps.client = client
        deps.policy = PocPolicy(runtime='claude_sdk', session_policy=QUEUE_POLICY).snapshot()
        deps.finding = {**deps.finding,
                        'poc': {'filename': 'check.py', 'language': 'python', 'script': script}}

    async def response():
        assert '# 宿主已执行审计记录的 POC' in sdk.calls[-1]['prompt']
        assert json.loads(await rt.call_tool('publish_verification', payload(rt._service)))['ok']
        yield ResultMessage(usage=dict(input_tokens=10, output_tokens=2), cost=.01)

    rt, sdk = runtime(tmp_path, [response, response], max_seconds=60)

    async def scenario():
        try:
            return (await invoke(rt, first, events, saved),
                    await invoke(rt, continued, events, saved))
        finally:
            await rt.aclose()

    asyncio.run(scenario())
    assert len(client.jobs) == 1
    assert [event['kind'] for event in events if event['kind'].startswith('poc_stored_poc')] \
        == ['poc_stored_poc_executed']


def test_legacy_policy_never_runs_the_recorded_poc(tmp_path):
    events, saved = [], []
    service_ = service(tmp_path)
    from tests.test_poc_agent import FakeClient
    client = FakeClient()
    service_.client = client
    service_.finding = {**service_.finding,
                        'poc': {'filename': 'check.py', 'language': 'python',
                                'script': "print(os.environ['LAB30_URL'])\n"}}

    async def response():
        assert client.jobs == []
        assert '# 宿主已执行审计记录的 POC' not in sdk.calls[0]['prompt']
        assert json.loads(await rt.call_tool('publish_verification', payload(rt._service)))['ok']
        yield ResultMessage(usage=dict(input_tokens=10, output_tokens=2), cost=.01)

    rt, sdk = runtime(tmp_path, [response], max_seconds=60)

    async def scenario():
        try:
            return await invoke(rt, service_, events, saved)
        finally:
            await rt.aclose()

    outcome = asyncio.run(scenario())
    assert outcome.result.status == 'inconclusive'
    assert client.jobs == [] and saved
    assert not any(event['kind'].startswith('poc_stored_poc') for event in events)
