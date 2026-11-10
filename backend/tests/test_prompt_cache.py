"""Cache accounting and prefix reuse through the real model and publication gates."""
import asyncio
import json
from types import SimpleNamespace

import pytest
from smolagents.models import ChatMessage, TokenUsage

from audit import agent
from audit.db import Store
from audit.prompt_cache import PromptCacheStats, cache_markdown, message_cache_usage, normalize_usage
from audit.runtime import AgentPolicy
from tests.code_model import Answer, Host, ModelFactory, Phase, code, transcript
from tests.test_planner_tools import project  # noqa: F401 - source snapshot fixture


@pytest.mark.parametrize('raw,total,read,source', [
    ({'prompt_tokens': 1000, 'prompt_tokens_details': {'cached_tokens': 600}}, 1000, 600, 'compatible'),
    ({'input_tokens': 1000, 'input_tokens_details': {'cached_tokens': 600}}, 1000, 600, 'compatible'),
    ({'prompt_tokens': 1000, 'prompt_cache_hit_tokens': 700, 'prompt_cache_miss_tokens': 300}, 1000, 700, 'deepseek'),
    ({'prompt_cache_hit_tokens': 700, 'prompt_cache_miss_tokens': 300}, 1000, 700, 'deepseek'),
    ({'prompt_tokens': 1000, 'prompt_tokens_details': {'cached_tokens': 0}}, 1000, 0, 'compatible'),
    ({'prompt_tokens': 1000}, 1000, None, 'unreported'),
    ({'prompt_tokens': 1000, 'prompt_cache_hit_tokens': 900, 'prompt_cache_miss_tokens': 200}, 1000, None, 'invalid'),
    ({'prompt_tokens': 1000, 'prompt_tokens_details': {'cached_tokens': 1001}}, 1000, None, 'invalid'),
    ({'prompt_tokens': 1000, 'prompt_tokens_details': {'cached_tokens': True}}, 1000, None, 'unreported'),
    ({'prompt_tokens': 1000, 'prompt_tokens_details': {'cached_tokens': -1}}, 1000, None, 'unreported'),
])
def test_normalizes_compatible_and_deepseek_without_inventing_hits(raw, total, read, source):
    assert normalize_usage(raw) == dict(input_tokens=total, cache_read_tokens=read,
                                       cache_write_tokens=None, source=source)


def test_native_anthropic_total_includes_read_and_creation_and_preserves_zero():
    native = normalize_usage(dict(input_tokens=100, cache_read_input_tokens=600, cache_creation_input_tokens=300), anthropic=True)
    assert native['input_tokens'] == 1000 and native['cache_read_tokens'] == 600
    assert normalize_usage(dict(input_tokens=100, cache_read_input_tokens=0, cache_creation_input_tokens=0), anthropic=True)['input_tokens'] == 100
    assert normalize_usage(dict(input_tokens=100, cache_read_input_tokens=600), anthropic=True)['input_tokens'] is None
    from audit.runtimes.claude_poc import _usage_from_result
    usage = _usage_from_result(SimpleNamespace(usage=dict(input_tokens=100, cache_read_input_tokens=0, cache_creation_input_tokens=0)))
    assert usage['cache_read_tokens'] == usage['cache_write_tokens'] == 0
    assert usage['prompt_cache']['input_tokens'] == 100


def test_sdk_objects_raw_usage_and_fallback_without_raw_response():
    response = ChatMessage(role='assistant', content='do not persist this', raw=SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=1000, prompt_tokens_details=SimpleNamespace(cached_tokens=700))),
        token_usage=TokenUsage(input_tokens=1000, output_tokens=10))
    assert message_cache_usage(response)['cache_read_tokens'] == 700
    response.raw = None
    assert message_cache_usage(response)['input_tokens'] == 1000
    assert message_cache_usage(response)['cache_read_tokens'] is None


def test_token_weighted_ratio_partial_coverage_and_zero_are_distinct():
    stats = PromptCacheStats()
    stats.add(normalize_usage(dict(prompt_tokens=100, prompt_cache_hit_tokens=100)))
    stats.add(normalize_usage(dict(prompt_tokens=900, prompt_cache_hit_tokens=0)))
    stats.add(normalize_usage(dict(prompt_tokens=3000)))
    view = stats.view()
    assert view['cache_hit_ratio'] == .1  # not the mean per-request ratio .5
    assert view['reported_input_tokens'] == 1000 and view['known_input_tokens'] == 4000
    assert view['record_coverage'] == 2/3 and not view['complete']
    assert PromptCacheStats.restore(view).view() == view
    text = '\n'.join(cache_markdown(view))
    assert '10.00%' in text and '2/3' in text and '仍消耗模型请求额度' in text


def test_persisted_projection_survives_restart_and_consumes_each_event_once(tmp_path):
    path = tmp_path/'audit.db'
    store = Store(path)
    raw = normalize_usage(dict(prompt_tokens=1000, prompt_cache_hit_tokens=800))
    store.append_event('r', None, 'model_response', dict(phase='task_publish', input_tokens=1000, prompt_cache=raw))
    store.append_event('r', None, 'model_response', dict(phase='planner_publish', input_tokens=2000))
    assert store.prompt_cache_usage('r')['usage_records'] == 2
    for _ in range(3):
        assert store.prompt_cache_usage('r')['cache_read_tokens'] == 800
    # Markers unrelated to usage advance the cursor too.
    e = store.append_event('r', None, 'run_paused', {})
    store.prompt_cache_usage('r')
    assert store._row('SELECT last_event_id FROM run_prompt_cache WHERE run_id=?', ('r',))[0] == e['id']
    store.close()
    store = Store(path)
    store.append_event('r', None, 'poc_runtime_usage', dict(usage=dict(input_tokens=100, cache_read_tokens=600, cache_write_tokens=300)))
    store.append_event('other-run', None, 'model_response', dict(input_tokens=10000, prompt_cache=raw))
    stats = store.prompt_cache_usage('r')
    assert stats['usage_records'] == 3 and stats['reported_records'] == 2
    assert stats['cache_read_tokens'] == 1400 and stats['reported_input_tokens'] == 2000
    assert stats['by_role']['poc_sdk']['cache_hit_ratio'] == .6
    store.close()


def test_live_run_usage_exposes_cache_before_task_commit_and_deletion_cleans_projection(tmp_path):
    from audit.source import SourceRepository
    from tests.test_goal_tasks import create_planner_run
    store = Store(tmp_path/'audit.db')
    run, _ = create_planner_run(store, SourceRepository(tmp_path/'sources'))
    cached = normalize_usage(dict(prompt_tokens=1000, prompt_cache_hit_tokens=700))
    store.append_event(run['id'], None, 'model_response', dict(phase='task_publish', prompt_cache=cached))
    assert store.get_run(run['id'])['usage']['prompt_cache']['cache_hit_ratio'] == .7
    store.request_cancel(run['id'])
    store.delete_run(run['id'])
    assert not store._row('SELECT * FROM run_prompt_cache WHERE run_id=?', (run['id'],))
    store.close()


@pytest.mark.parametrize('legacy', [False, True])
def test_readonly_archive_uses_only_memory_and_never_migrates_or_writes(tmp_path, legacy):
    import hashlib
    path = tmp_path/'archive.db'
    store = Store(path)
    store.append_event('r', None, 'model_response', dict(input_tokens=1000,
        prompt_cache=normalize_usage(dict(prompt_tokens=1000, prompt_cache_hit_tokens=700))))
    if legacy:
        store._db.execute('DROP TABLE run_prompt_cache')
    store.close()
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    archive = Store.open_readonly(path)
    assert archive.prompt_cache_usage('r')['cache_hit_ratio'] == .7
    assert archive.prompt_cache_usage('r')['usage_records'] == 1
    archive.close()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    assert {p.name for p in tmp_path.iterdir()} == {'archive.db'}


def test_normal_and_summary_responses_preserve_cache_usage_in_events_and_snapshots():
    host = Host({})
    phase = Phase(host, output_model=Answer)
    response = ChatMessage(role='assistant', content=code("final_answer({'note':'done'})"),
        raw={'usage': {'prompt_tokens': 1000, 'prompt_cache_hit_tokens': 800}},
        token_usage=TokenUsage(input_tokens=1000, output_tokens=10))
    async def play():
        gate = phase.gate()
        await gate._record(response)
        await gate._record_summary(ChatMessage(role='assistant', content='源码已读，尚未完成的路径与缺失配置仍须继续检查。',
            raw={'usage': {'prompt_tokens': 100, 'prompt_cache_hit_tokens': 0}},
            token_usage=TokenUsage(input_tokens=100, output_tokens=20)), prompt_bytes=300)
    asyncio.run(play())
    events = [e for e in host.events if e['kind'] == 'model_response']
    assert len(events) == 2 and events[-1]['purpose'] == 'history_summary'
    view = host.execution.snapshot()['prompt_cache']
    assert view['usage_records'] == 2 and view['cache_hit_ratio'] == 800/1100
    assert host.execution.usage.requests == 2


def test_code_prompt_is_stable_across_private_parser_nonces():
    one = Phase(Host({}), output_model=Answer).play([code("final_answer({'note':'one'})")])
    two = Phase(Host({}), output_model=Answer).play([code("final_answer({'note':'two'})")])
    assert one.failure is two.failure is None
    assert one.gate.action_tags != two.gate.action_tags
    first = transcript([one.model.requests[0][0]])
    assert first == transcript([two.model.requests[0][0]])
    assert '<audit_action_' not in first and '<code>' in first


def test_worker_schema_is_in_stable_prefix_and_latest_findings_remain_in_user_data(monkeypatch):
    from tests.test_finding_reuse import TASK, known, assessment, reference
    from tests.test_worker_strategies import CONFIG, Repository, UNIT
    systems = []
    for ident in ('root-before', 'root-after'):
        item = known(ident)
        factory = ModelFactory([json.dumps(assessment(reference(item)), ensure_ascii=False)])
        monkeypatch.setattr(agent, 'build_code_model', factory)
        outcome = asyncio.run(agent.pursue_task_work(repository=Repository(), snapshot_id='snapshot', snapshot_name='demo.zip',
            unit=UNIT, task=TASK, attempt=1, current_run_id='run', current_findings=[item], config=CONFIG,
            budgets=dict(responses=3, tools=0, seconds=10), policy=AgentPolicy(request_seconds=1, worker_explore_responses=0)))
        assert outcome['outcome'] == 'achieved', outcome
        messages = factory.built().requests[0]
        system, user = transcript([messages[0]]), transcript(messages[1:])
        assert ident not in system and ident in user
        assert '# 完整 JSON 字段契约' in system and '# 完整 JSON 字段契约' not in user
        systems.append(system)
    assert systems[0] == systems[1]


def test_planner_round_counter_follows_the_reusable_frozen_project_map(project, monkeypatch):
    from tests.test_planner_tools import CONFIG, TASK, decision_payload
    prefixes = []
    for round_no in (1, 2):
        factory = ModelFactory([json.dumps(decision_payload(), ensure_ascii=False)])
        monkeypatch.setattr(agent, 'build_code_model', factory)
        outcome = asyncio.run(agent.plan_audit_frontier(project_map=project.project_map, run_context={},
            task=TASK, round_no=round_no, config=CONFIG, budgets=dict(responses=3, tools=0, seconds=10),
            policy=AgentPolicy(planner_explore_responses=0, decision_confirmations=0),
            repository=project.repository, snapshot_id=project.snapshot_id))
        assert outcome['decision'] is not None, outcome
        user = transcript(factory.built().requests[0][1:])
        prefix, tail = user.split('当前 Planner 回合：', 1)
        assert '主机生成的项目结构概览' in prefix and tail.startswith(str(round_no))
        prefixes.append(prefix)
    assert prefixes[0] == prefixes[1]


def test_final_report_freezes_the_same_cache_facts_in_json_and_markdown():
    from tests.test_final_review_bundle import accepted, bundle, render
    stats = PromptCacheStats()
    stats.add(normalize_usage(dict(prompt_tokens=1000, prompt_cache_hit_tokens=600)), 'worker')
    payload = bundle([accepted('f1')])
    payload['run']['usage'] = {'prompt_cache': stats.view()}
    facts, markdown = render(payload)
    assert facts['appendix']['usage']['prompt_cache'] == stats.view()
    assert '### API 提示缓存' in markdown and '60.00%' in markdown
    # Rendering uses frozen facts, not the subsequently changed run counters.
    payload['run']['usage']['prompt_cache']['cache_hit_ratio'] = .9
    from audit.report_final import render_final_report
    assert '60.00%' in render_final_report(facts)
