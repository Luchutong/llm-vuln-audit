"""Offline reproductions of the eight corrections and their host boundaries."""
import asyncio
import json

import pytest

from audit.actions import extract_action
from audit.agent import AuditDeps
from audit.evidence import validate_evidence
from audit.navigation import ProjectIndex
from audit.runtime import AgentPolicy, Execution, SourceLedger
from audit.tool_errors import public_value
from audit.toolkit import WORKER_TOOLS, Arg, spec
from tests.code_model import Answer, Host, Phase, code, final_answer
from tests.test_agent_runtime import Repository, UNIT


@pytest.mark.parametrize('reply', ['已完成，请查看结果。', "final_answer({'note': 'outside a fence'})", '本次结论以正文给出，未提交动作。', '需要补充信息后再执行工具。'])
def test_four_sanitized_format_errors_recover_without_persisting_prose(reply):
    host = Host()
    result = Phase(host, output_model=Answer).play([reply, final_answer({'note': 'recovered'})])
    assert result.failure is None and result.gate.published.note == 'recovered'
    events = host.events_of('agent_parse_error')
    assert len(events) == 1 and events[0]['diagnostics']['closed_blocks'] == 0
    assert all(reply not in json.dumps(event, ensure_ascii=False) for event in host.events)
    assert host.events_of('agent_error_summary')[0]['categories']['no_code_block'] == {'errors': 1, 'recovered': 1}


def test_incomplete_loop_is_rejected_before_any_tool_is_called():
    host = Host({'read_source': 'x'})
    result = Phase(host, specs=WORKER_TOOLS, output_model=Answer).play([
        code("print(read_source('a.php', 1, 1))\nfor item in []"), final_answer({'note': 'corrected'}),
    ])
    assert result.failure is None and host.calls == []
    failure = host.events_of('agent_execution_error')[0]
    assert failure['category'] == 'invalid_python' and failure['diagnostics']['syntax_line'] == 2


def test_base64_and_preloaded_json_prevent_two_import_state_errors():
    host = Host()
    result = Phase(host, output_model=Answer).play([
        code("import base64\nassert base64.b64decode('e30=').decode() == '{}'\nassert json.loads('{}') == {}"),
        code('import socket\nvalue = 1'),
        code("final_answer({'note': json.loads('{\"ok\":\"recovered\"}')[\"ok\"]})"),
    ])
    assert result.failure is None and result.gate.published.note == 'recovered'
    assert host.events_of('agent_execution_error')[0]['category'] == 'unauthorized_import'


def test_omitted_archive_root_only_suggests_paths_already_read():
    ranges = [('archive/app/main.php', 4, 8)]
    refs = [{'path': 'app/main.php', 'start_line': 4, 'end_line': 8}]
    files = {'archive/app/main.php': 10, 'private/app/main.php': 10}
    verified, errors = validate_evidence(refs, files, ranges)
    assert not verified and 'archive/app/main.php' in errors[0] and 'private/app/main.php' not in errors[0]
    assert not validate_evidence([{**refs[0], 'path': 'archive/app/main.php'}], files, ranges)[1]
    assert not validate_evidence([{**refs[0], 'path': 'archive/app/main.php', 'start_line': True}], files, ranges)[0]


def test_nested_directory_paths_can_be_reused_verbatim():
    index = ProjectIndex(directories=['archive', 'archive/app', 'archive/app/lib'], files_by_path={
        'archive/app/lib/a.php': {'line_count': 2}, 'archive/app/b.php': {'line_count': 1},
    })
    first = json.loads(index.listing({'path': 'archive', 'depth': 1}))
    directory = first['child_directories'][0]['path']
    assert directory == 'archive/app'
    nested = json.loads(index.listing({'path': directory, 'depth': 1}))
    assert nested['child_directories'][0] == {'path': 'archive/app/lib', 'files_below': 1}
    assert nested['files_here'][0]['path'] == 'archive/app/b.php'


@pytest.mark.parametrize('body', ["read_source('a.php', True, 3)", "read_source(['a.php'], 1, 3)", "read_source('a.php', 4, 3)", "search_code('x', path=4)"])
def test_invalid_arguments_are_charged_once_and_never_dispatch(body):
    host = Host()
    result = Phase(host, specs=WORKER_TOOLS, output_model=Answer).play([code(body), final_answer({'note': 'recovered'})])
    assert result.failure is None and host.calls == [] and host.execution.tools == 1
    event = host.events_of('tool_result')[0]
    assert event['error_code'] == 'invalid_arguments' and event['args']
    assert event['call_id'] and event['span_id'] and event['phase'] and event['hint']


def test_ambiguous_blocks_never_execute_either_action():
    host = Host({'read_source': 'x'})
    result = Phase(host, specs=WORKER_TOOLS, output_model=Answer).play([
        code("read_source('a.php', 1, 1)") + '\n' + code("read_source('b.php', 1, 1)"), final_answer({'note': 'corrected'}),
    ])
    assert result.failure is None and host.calls == []
    assert host.events_of('agent_parse_error')[0]['category'] == 'ambiguous_code_blocks'


def test_markdown_compatibility_and_incomplete_transport_diagnostics():
    result = Phase(Host(), output_model=Answer).play(["```python\nfinal_answer({'note': 'markdown'})\n```"])
    assert result.failure is None and result.gate.published.note == 'markdown'
    assert extract_action('<code>\nfor row in []')[2].category == 'incomplete_code'
    assert extract_action("<code>\nprint('complete')", 'length')[2].category == 'incomplete_code'
    assert extract_action("<code>\nprint('complete')", 'stop')[1]['closing_tag_omitted']


def make_deps(events):
    execution = Execution({'responses': 10, 'tools': 10, 'seconds': 30}, AgentPolicy(repeated_calls=10, no_progress_calls=10), events.append)
    execution.enter('task_execute')
    return AuditDeps(Repository(), 's1', UNIT, execution, SourceLedger(8192))


def test_timeout_is_not_cached_and_only_one_explicit_retry_reaches_source():
    async def scenario():
        events, attempts = [], []
        deps = make_deps(events)
        async def fail(args):
            attempts.append(args)
            raise TimeoutError('source lookup timed out')
        deps.read_source_text = fail
        for _ in range(3):
            await deps.call('read_source', {'path': 'a.php', 'start': 1, 'end': 3})
        assert len(attempts) == 2 and deps.execution.tools == 3 and not deps.call_results
        assert [event['error_code'] for event in events if event['kind'] == 'tool_result'] == ['timeout', 'timeout', 'retry_exhausted']
    asyncio.run(scenario())


def test_transient_recovery_and_missing_file_cache_keep_correct_status():
    async def scenario():
        events, calls = [], []
        deps = make_deps(events)
        def navigation(args):
            calls.append(args)
            if len(calls) == 1:
                raise TimeoutError('temporarily busy')
            return '{"path":"archive","files_here":[]}'
        deps.local_tools['list_tree'] = navigation
        assert json.loads(await deps.call('list_tree', {'path': 'archive'}))['error_code'] == 'timeout'
        assert json.loads(await deps.call('list_tree', {'path': 'archive'}))['path'] == 'archive'
        assert deps.execution.tool_diagnostics['task_execute']['timeout']['recovered'] == 1
        def missing(args):
            raise FileNotFoundError('source file absent')
        deps.local_tools['file_summary'] = missing
        for _ in range(2):
            assert json.loads(await deps.call('file_summary', {'path': 'missing.php'}))['error_code'] == 'path_not_found'
        event = [event for event in events if event['kind'] == 'tool_result'][-1]
        assert event['status'] == 'context_missing' and event['cache_hit']
    asyncio.run(scenario())


def test_argument_redaction_and_array_element_contract():
    sanitized = public_value({'password': 'private', 'headers': {'Authorization': 'Bearer private'}, 'query': 'public', 'body': 'password=private'})
    assert 'private' not in json.dumps(sanitized) and sanitized['query'] == 'public'
    declared = spec('artifacts', 'test', files=Arg('array', 'filenames', item_type='string', max_items=2))
    with pytest.raises(TypeError):
        declared.bind((), {'files': [True]})
    with pytest.raises(TypeError):
        declared.bind((), {'files': ['a', 'b', 'c']})


def test_json_tool_argument_failure_is_parseable_without_dispatch():
    from audit.toolkit import PLANNER_TOOLS
    host = Host()
    result = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([
        code("value = json.loads(list_tree(depth=True))\nassert value['error_code'] == 'invalid_arguments'\nfinal_answer({'note': 'checked'})"),
    ])
    assert result.failure is None and host.calls == [] and host.execution.tools == 1


@pytest.mark.parametrize('wrapper', ['xml', 'markdown'])
@pytest.mark.parametrize('script', [
    'print("<code>normal</code>")\nprint("after")\n',
    'print("before")\n```python\nprint("quoted fence")\n```\nprint("after")\n',
])
def test_runner_script_literals_survive_both_transport_parsers(wrapper, script):
    tool = spec('run_poc', 'Offline runner stub', script=Arg('string', 'script'))
    host = Host({'run_poc': 'job completed'})
    body = "import base64\nscript = '''" + script + "'''\nprint(run_poc(script=script))\nfinal_answer({'note':'preserved'})"
    reply = code(body) if wrapper == 'xml' else '```python\n' + body + '\n```'
    result = Phase(host, specs=(tool,), output_model=Answer).play([reply])
    assert result.failure is None and result.gate.published.note == 'preserved'
    assert host.calls == [('run_poc', {'script': script})]
    assert not host.events_of('agent_parse_error')


@pytest.mark.parametrize('probe', ['import base64\nbase64.main()', 'from base64 import main\nmain()', 'import base64 as b\nb.encode(None, None)'])
def test_base64_file_helpers_cannot_reach_host_open(monkeypatch, probe):
    import base64
    opened = []
    def forbidden_open(*args, **kwargs):
        opened.append(args)
        raise AssertionError('host open reached')
    monkeypatch.setattr(base64, 'open', forbidden_open, raising=False)
    host = Host()
    result = Phase(host, output_model=Answer).play([code(probe), final_answer({'note': 'bounded'})])
    assert result.failure is None and opened == []
    assert host.events_of('agent_execution_error')


def test_repeated_json_argument_failures_cannot_bypass_correction_budget():
    from audit.toolkit import PLANNER_TOOLS
    from tests.code_model import Always
    host = Host(policy=AgentPolicy(output_corrections=2))
    result = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play(Always([code("print(json.loads(list_tree(depth=True)))")]))
    assert result.reason() == 'invalid_output' and len(result.model.requests) == 3
    assert host.calls == [] and host.execution.tools == 3 and host.execution.corrections == 2


def test_json_tool_error_corrected_inside_same_action_does_not_spend_model_retry():
    from audit.toolkit import PLANNER_TOOLS
    host = Host({'list_tree': '{"files_here":[]}'})
    result = Phase(host, specs=PLANNER_TOOLS, output_model=Answer).play([code(
        "bad = json.loads(list_tree(depth=True))\nassert bad['ok'] is False\n"
        "good = json.loads(list_tree(depth=1))\nassert good['files_here'] == []\nfinal_answer({'note':'corrected'})"
    )])
    assert result.failure is None and host.execution.corrections == 0
    assert len(host.calls) == 1 and host.execution.tools == 2
    assert host.events_of('agent_error_summary')[0]['tool_categories']['invalid_arguments']['recovered'] == 1
