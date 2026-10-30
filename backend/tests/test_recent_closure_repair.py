"""Failures seen in b8f423a9, replayed with temporary data and simulated models."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from audit import agent
from audit.config import PocSettings
from audit.final_review import canonical_groups, comparison_candidates
from audit.poc import PocPolicy, PocVerifier, _attempt_responses
from audit.runtime import AgentPolicy
from audit.runtimes.claude_poc import ClaudeCodePocRuntime, PocRuntimeOutcome
from tests.code_model import CONFIG, ModelFactory, code
from tests.test_host_queue import hosted, add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_review_input_repair import read_all, decisions
from tests.test_claude_poc_runtime import http_job, service


def failed_finding(store, run):
    finding = add_claim(store, run, 1, verified=True)
    v = store.get_finding(finding['id'])['verifications'][-1]
    data = {**v['agent'], 'context_id': 'ctx-1', 'reason': 'sdk_cleanup_timeout',
            'job_results': [http_job(body='NORMAL_PAGE original body')], 'jobs': ['job-1']}
    store._write("UPDATE verifications SET agent=?,status='inconclusive',verdict='uncertain',normal_observation='',attack_observation='' WHERE id=?",
                 (json.dumps(data), v['id']))
    store._write("UPDATE findings SET verification_status='inconclusive',verification_verdict='uncertain' WHERE id=?", (finding['id'],))
    return finding


@pytest.mark.parametrize('saved_reason', ['sdk_cleanup_timeout', None, 'completed'])
def test_failed_poc_requires_original_job_reads_even_when_the_batch_is_small(hosted, saved_reason):
    store, repo, run = hosted
    finding = failed_finding(store, run)
    saved = store.get_finding(finding['id'])['verifications'][-1]
    saved['agent']['reason'] = saved_reason
    store._write('UPDATE verifications SET agent=? WHERE id=?', (json.dumps(saved['agent']), saved['id']))
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    assert len(json.dumps(batch['items'], ensure_ascii=False).encode()) < 32768
    assert item['required_read_fields'] == ['payload.verification_job_facts']
    assert item['payload']['verification_observations']['fact_availability']['successful_jobs'] == 1
    assert 'verification_job_facts' not in item['payload']
    with pytest.raises(ValueError, match='已保存成功作业'):
        store.validate_review_decisions(run['id'], batch, decisions(batch, 'contested'))
    read_all(store, repo, run, batch, item)
    assert store.validate_review_decisions(run['id'], batch, decisions(batch, 'contested'))
    assert store.get_finding(finding['id'])['verification_status'] == 'inconclusive'


def test_failed_poc_has_a_real_read_and_publish_path_without_new_experiments(hosted, monkeypatch):
    store, repo, run = hosted
    failed_finding(store, run)
    store.set_workflow_stage(run['id'], 'review')
    batch = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    item = batch['items'][0]
    request = dict(goal_state='continue', basis_summary='有正常侧原文，攻击影响仍未证实。', review_batch_id=batch['id'],
                   review_decisions=decisions(batch, 'contested'))
    body = f"""
import json
for part in {item['paged_fields']!r}:
    offset = 0
    while offset is not None:
        page = json.loads(read_review_input({item['item_id']!r}, part['field'], offset))
        print(page['text'])
        offset = page['next_offset']
"""
    factory = ModelFactory([code(body), code(f'final_answer({request!r})')])
    monkeypatch.setattr(agent, 'build_code_model', factory)
    context = {**store.list_planner_context(run['id'], project_map=store.get_project_map(run['id'])), 'review_batch': batch}
    events = []
    outcome = asyncio.run(agent.plan_audit_frontier(
        project_map=store.get_project_map(run['id']), run_context=context, task=run['task_spec'],
        round_no=1, config=CONFIG, budgets={'responses': 12, 'tools': 100, 'seconds': 10},
        policy=AgentPolicy(request_seconds=.5), repository=repo, snapshot_id=run['snapshot_id'],
        allowed_paths=set(run['scope']), pins=store, run_id=run['id'], on_event=events.append))
    assert outcome['decision'], outcome
    assert outcome['usage']['requests'] == 2
    assert {e['tool'] for e in events if e['kind'] == 'tool_call'} == {'read_review_input'}


def test_cross_file_chain_is_compared_but_shared_helpers_alone_do_not_match():
    def claim(ident, path, line, refs):
        return dict(id=ident, project_finding_id=ident, finding_kind='vulnerability', validation_state='candidate',
                    vulnerability_type='session_fixation', primary_location=dict(path=path, line=line),
                    evidence=[dict(path=p, start_line=a, end_line=b) for p,a,b in refs])
    entries, _ = canonical_groups([
        claim('login', 'auth/login.php', 8, [('auth/login.php', 3, 9), ('bootstrap.php', 13, 18)]),
        claim('helper', 'bootstrap.php', 17, [('bootstrap.php', 13, 18), ('auth/login.php', 3, 9)]),
        claim('other', 'auth/other.php', 2, [('auth/other.php', 1, 3), ('bootstrap.php', 33, 36)]),
        claim('third', 'auth/third.php', 2, [('auth/third.php', 1, 3), ('bootstrap.php', 33, 36)]),
    ])
    peers = comparison_candidates(entries)
    assert peers['login'][0]['item_id'] == 'helper'
    assert 'other' not in peers and 'third' not in peers
    assert len(entries) == 4  # Comparison does not merge or discard a record.


def test_related_entries_are_packed_together_within_the_existing_byte_cap(hosted):
    store, repo, run = hosted
    for i in range(10):
        f = add_claim(store, run, i, ledger=f'ledger-{i:02}')
        if i in (0, 9):
            store._write('UPDATE findings SET primary_location=? WHERE id=?',
                         (json.dumps({'path': 'public/index.php', 'line': i % 3 + 1}), f['id']))
    groups = store.review_batches_pending(run['id'], 'final', repo)
    first = {i['item_id'] for i in groups[0]}
    assert {'ledger-00', 'ledger-09'}.issubset(first)
    assert all(len(json.dumps(g, ensure_ascii=False).encode()) < 34000 for g in groups)


def test_split_related_batches_carry_the_prior_exact_version_decision(hosted):
    store, repo, run = hosted
    for i in (0, 1):
        f = add_claim(store, run, i, ledger=f'ledger-{i}', verified=True)
        store._write('UPDATE findings SET primary_location=? WHERE id=?',
                     (json.dumps({'path': 'public/index.php', 'line': i + 1}), f['id']))
        store._write('UPDATE verifications SET normal_observation=? WHERE finding_id=?', ('完整正常观测。' * 650, f['id']))
    first = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    assert len(first['items']) == 1  # The pair exceeds the byte ceiling as a unit.
    values = decisions(first, 'needs_evidence')
    plan = store.begin_planner_round(run['id'], store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'], plan['id'], goal_state='continue', basis_summary='已读原文后明确保留必要前提未决。',
                               review_batch_id=first['id'], review_decisions=values)
    second = store.prepare_review_batch(run['id'], 'final', run['execution_epoch'], repo)
    prior = second['items'][0]['payload']['related_review_decisions']
    assert prior[first['items'][0]['item_id']]['decision'] == 'needs_evidence'
    assert prior[first['items'][0]['item_id']]['revision'] == first['items'][0]['revision']


def test_new_cross_file_gate_does_not_retroactively_require_old_distinctions():
    from audit.report_quality import evaluate
    from tests.test_final_review_bundle import finding, bundle, render
    records = [dict(finding('one', status='unverified'), vulnerability_type='session_fixation',
                    primary_location={'path': 'auth/login.php', 'line': 8}),
               dict(finding('two', status='unverified'), vulnerability_type='session_fixation',
                    primary_location={'path': 'bootstrap.php', 'line': 17})]
    facts, _ = render(bundle(records))
    for entry in facts['canonical_findings']:
        entry.update(final_disposition='accepted', final_batch_review={'input_policy': 'paged-facts-v1', 'distinct_from': []},
                     comparison_candidates=[{'item_id': 'peer', 'basis_kind': 'cited_anchor'}])
    assert 'comparison_candidates_adjudicated' not in evaluate(facts)['failed_checks']
    for entry in facts['canonical_findings']:
        entry['final_batch_review']['input_policy'] = 'paged-facts-v2'
    assert 'comparison_candidates_adjudicated' in evaluate(facts)['failed_checks']


def test_sdk_quotas_are_frozen_separately_from_legacy_steps(monkeypatch, tmp_path):
    cfg = PocSettings.from_environ({'POC_RUNTIME': 'claude_sdk', 'POC_MAX_STEPS': '8',
        'POC_CLAUDE_EXECUTE_REQUESTS': '18', 'POC_CLAUDE_CONCLUDE_REQUESTS': '3'})
    frozen = cfg.snapshot()
    assert frozen['sdk_requests'] == {'version': 'sdk-requests-v1', 'execute': 18, 'conclude': 3}
    settings = SimpleNamespace(poc=cfg)
    new = PocPolicy.from_run({'poc_policy': frozen}, settings)
    old = PocPolicy.from_run({'poc_policy': {'runtime': 'claude_sdk', 'max_steps': 8}}, settings)
    assert _attempt_responses(new, 100) == 21 and _attempt_responses(new, 5) == 5
    assert _attempt_responses(old, 100) == 11
    captured = []
    async def verify(runtime, **kwargs):
        captured.append(runtime.limits)
        return PocRuntimeOutcome('completed', None, 'completed', {})
    monkeypatch.setattr(ClaudeCodePocRuntime, 'verify', verify)
    monkeypatch.setenv('POC_CLAUDE_EXECUTE_REQUESTS', '40')
    deps = service(tmp_path)
    deps.policy.update(new.snapshot(), max_responses=21)
    verifier = PocVerifier.__new__(PocVerifier)
    verifier.store = SimpleNamespace()
    asyncio.run(verifier._verify_with_sdk({'execution_epoch': 1}, deps, lambda _: None, 'run'))
    assert captured[0].execute_requests == 18 and captured[0].conclude_requests == 3


def test_bad_sdk_deployment_limits_do_not_disable_static_app_configuration():
    config = PocSettings.from_environ({'POC_RUNTIME': 'claude_sdk', 'POC_CLAUDE_EXECUTE_REQUESTS': 'invalid'})
    assert config.runtime == 'claude_sdk'
    assert config.snapshot()['sdk_requests']['execute'] == 40
    from audit.runtimes.claude_poc import ClaudePocLimits
    with pytest.raises(ValueError, match='POC_CLAUDE_EXECUTE_REQUESTS'):
        ClaudePocLimits.from_environ({'POC_CLAUDE_EXECUTE_REQUESTS': 'invalid'})


def test_report_preserves_failed_poc_job_facts_without_inventing_a_conclusion():
    from tests.test_final_review_bundle import finding, verification, bundle, render
    v = verification('v1', verdict='uncertain')
    v.update(status='inconclusive', target={}, normal_observation='', attack_observation='',
             agent={'context_id': 'ctx-1', 'run_finding_revision': 1, 'jobs': [],
                    'job_results': [http_job()], 'reason': 'sdk_cleanup_timeout',
                    'usage': {'execute_reason': 'sdk_cleanup_timeout'}})
    facts, markdown = render(bundle([finding('f1', status='inconclusive', verdict='uncertain', verifications=[v])]))
    assert facts['provenance']['renderer_version'] == 'final-report/v2'
    attempt = facts['verification_attempts'][0]
    assert attempt['context_id'] == 'ctx-1'
    assert attempt['job_refs'] == []  # Saved facts are not promoted to supporting references.
    assert attempt['observed_job_ids'] == ['job-1']
    assert attempt['fact_availability']['successful_jobs'] == 1
    assert attempt['fact_availability']['conclusion_missing']
    assert attempt['normal_evidence'] == attempt['attack_evidence'] == ''
    assert facts['counts']['accepted'] == 0
    assert '已保存作业事实：1 个' in markdown
    assert '结论未完整发布' in markdown and 'sdk_cleanup_timeout' in markdown
    assert 'job-1' in markdown


def test_sdk_generation_policy_is_frozen_and_verified_not_merely_claimed(monkeypatch, tmp_path):
    cfg = PocSettings.from_environ({'POC_RUNTIME': 'claude_sdk'})
    frozen = cfg.snapshot()['sdk_generation']
    assert frozen == {'version': 'sdk-generation-v1', 'output_policy': 'bounded-v1',
                      'execute_output_tokens': 4096, 'publish_output_tokens': 1024,
                      'thinking': 'disabled'}
    assert cfg.public()['sdk_generation'] == frozen
    assert PocSettings.from_environ({}).snapshot().get('sdk_generation') is None

    settings = SimpleNamespace(poc=cfg)
    new = PocPolicy.from_run({'poc_policy': cfg.snapshot()}, settings)
    old = PocPolicy.from_run({'poc_policy': {'runtime': 'claude_sdk'}}, settings)
    assert new.sdk_generation == frozen and new.snapshot()['sdk_generation'] == frozen
    # A run that predates the block keeps provider defaults; no server default is injected.
    assert old.sdk_generation is None and 'sdk_generation' not in old.snapshot()

    captured = []
    async def verify(runtime, **kwargs):
        captured.append(runtime.limits)
        return PocRuntimeOutcome('completed', None, 'completed', {})
    monkeypatch.setattr(ClaudeCodePocRuntime, 'verify', verify)
    monkeypatch.setenv('POC_SDK_EXECUTE_OUTPUT_TOKENS', '9000')
    deps = service(tmp_path)
    deps.policy.update(new.snapshot(), max_responses=21)
    verifier = PocVerifier.__new__(PocVerifier)
    verifier.store = SimpleNamespace()
    asyncio.run(verifier._verify_with_sdk({'execution_epoch': 1}, deps, lambda _: None, 'run'))
    assert captured[0].execute_output_tokens == 4096 and captured[0].thinking == 'disabled'
    assert captured[0].generation().snapshot()['output_policy'] == 'bounded-v1'


def test_invalid_sdk_generation_settings_fail_fast_and_are_reported(monkeypatch, tmp_path):
    for env, value in (('POC_SDK_OUTPUT_POLICY', 'unlimited'), ('POC_SDK_THINKING', 'on'),
                       ('POC_SDK_EXECUTE_OUTPUT_TOKENS', '0'),
                       ('POC_SDK_PUBLISH_OUTPUT_TOKENS', 'many')):
        with pytest.raises(ValueError, match=env):
            PocSettings.from_environ({'POC_RUNTIME': 'claude_sdk', env: value})

    emitted = []
    async def verify(runtime, **kwargs):  # must never run for a malformed frozen block
        raise AssertionError('runtime must not start')
    monkeypatch.setattr(ClaudeCodePocRuntime, 'verify', verify)
    deps = service(tmp_path)
    deps.policy.update(PocPolicy.from_run({'poc_policy': {
        'runtime': 'claude_sdk',
        'sdk_generation': {'version': 'sdk-generation-v1', 'output_policy': 'bounded-v1',
                           'execute_output_tokens': 4096, 'publish_output_tokens': 1024,
                           'thinking': 'enabled'}}}, SimpleNamespace(poc=PocSettings.from_environ(
                               {'POC_RUNTIME': 'claude_sdk'}))).snapshot())
    verifier = PocVerifier.__new__(PocVerifier)
    verifier.store = SimpleNamespace()
    verifier.bus = SimpleNamespace(emit=lambda *args: emitted.append(args))
    _, status, _ = asyncio.run(verifier._verify_with_sdk({'execution_epoch': 1}, deps, lambda _: None, 'run'))
    assert status == 'runtime_misconfigured'
    assert any(args[2] == 'poc_runtime_misconfigured' for args in emitted)
    assert 'thinking' in emitted[0][3]['error']
