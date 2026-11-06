"""Publication/SQLite receipt parity and containment of rejected worker results."""
import asyncio
import copy

import pytest

from audit import worker as worker_module
from audit.evidence import seen_ranges
from audit.execution_state import CURRENT_EXECUTION
from audit.role_policy import merge_candidates, validate_assessment, validate_disproof
from tests.test_audit_directions import commit
from tests.test_goal_tasks import make_worker, proposal, worker_outcome
from tests.test_worker_evidence_roles import (  # noqa: F401 — isolated source/SQLite fixtures
    owned, exhaustive, hosted, state, PATH, REF, SEEN, TASK, LINES, candidate, disproof, finding, lead,
)


@pytest.mark.parametrize('reads', [
    [dict(path=PATH, start_line=n, end_line=n) for n in (4, 2, 1, 3)],
    [dict(path=PATH, start_line=1, end_line=2), dict(path=PATH, start_line=3, end_line=4)],
    [dict(path=PATH, start_line=1, end_line=3), dict(path=PATH, start_line=2, end_line=4)],
])
def test_all_role_evidence_checks_accept_adjacent_delivered_reads(reads):
    result = dict(outcome='achieved', findings=[finding()], candidate_updates=[candidate()])
    published = [dict(path=p, start_line=a, end_line=b) for p, a, b in seen_ranges({}, reads, exact=True)]
    expected = validate_assessment(TASK, result, published, LINES)
    assert validate_assessment(TASK, result, reads, LINES) == expected
    spans = [(r['path'], r['start_line'], r['end_line']) for r in reads]
    assert validate_disproof(disproof(), spans)['evidence'] == [REF]
    assert merge_candidates([], [candidate()], [], spans, LINES) == expected


@pytest.mark.parametrize('reads', [
    [dict(path=PATH, start_line=1, end_line=2), dict(path=PATH, start_line=4, end_line=4)],
    [dict(path=PATH, start_line=1, end_line=2), dict(path='other.php', start_line=3, end_line=4)],
])
def test_merging_receipts_never_grants_missing_lines_or_other_files(reads):
    spans = [(r['path'], r['start_line'], r['end_line']) for r in reads]
    with pytest.raises(ValueError, match='实际读取'):
        validate_assessment(TASK, dict(findings=[finding()]), reads, LINES)
    with pytest.raises(ValueError, match='实际读取'):
        validate_disproof(disproof(), spans)
    with pytest.raises(ValueError, match='实际读取'):
        merge_candidates([], [candidate()], [], spans, LINES)


def test_sqlite_preserves_line_receipts_while_accepting_multiline_citations(owned):
    store, _, run = owned
    commit(store, run, tasks=[proposal('fragmented-reads')])
    task = store.claim_ready_task(run['id'], 'worker')
    reads = [dict(path=PATH, start_line=n, end_line=n) for n in range(1, 5)]
    result = dict(summary='引用实际逐行读取的连续源码区间。', findings=[finding()],
                  candidate_updates=[candidate('supported', finding_index=0)])
    settled = store.resolve_task_attempt(task['id'], 'worker', outcome='achieved',
        result=result, usage={}, seen=reads, terminal_reason='completed')
    assert settled['state'] == 'completed'
    assert store.list_task_attempts(task['id'])[0]['seen'] == reads
    assert settled['result']['candidate_journal'][0]['status'] == 'supported'


def test_direction_disproof_can_be_resolved_from_immutable_single_line_receipts(owned):
    store, _, run = owned
    item = lead(owned)
    commit(store, run, tasks=[{**proposal('negative-recheck'), 'direction_ids': [item['id']]}])
    task = store.claim_ready_task(run['id'], 'worker')
    reads = [dict(path=PATH, start_line=n, end_line=n) for n in range(1, 5)]
    store.resolve_task_attempt(task['id'], 'worker', outcome='no_evidence', result=dict(
        summary='核对了该方向的具体防护并保留逐行读取凭据。', direction_results=[dict(
            direction_id=item['id'], outcome='no_evidence', rationale='实际源码中的参数化防护适用于当前输入路径。',
            disproof=disproof())]), usage={}, seen=reads, terminal_reason='completed')
    commit(store, run, directions=[dict(direction_id=item['id'], action='resolve', task_key='negative-recheck',
        rationale_summary='对应 immutable attempt 的实际防护证据已充分读取。')])
    assert store.audit_direction_summary(run['id'])['complete']
    assert store.list_task_attempts(task['id'])[0]['seen'] == reads


def test_worker_commit_rejection_blocks_only_that_task_and_preserves_peers(owned, monkeypatch):
    store, repo, run = owned
    calls = []
    rejected_payloads = []
    async def planner(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        if not store.list_tasks(run['id']):
            decision = dict(goal_state='continue', basis_summary='两条独立方向分别取证。',
                tasks=[proposal('bad-citation'), proposal('valid-peer')])
        else:
            calls.append('after-workers')
            decision = dict(goal_state='inconclusive', basis_summary='一条方向的引用被拒，保留缺口和同伴成果。')
        return dict(decision=decision, usage={'requests': 1}, terminal_reason='completed')

    async def source(**kwargs):
        CURRENT_EXECUTION.get().admit('responses')
        key = kwargs['planner_task']['task_key']
        calls.append(key)
        claim = dict(title='输入进入敏感文件读取', kind='vulnerability', severity='high',
            summary='请求参数进入敏感文件读取操作，源码给出了对应输入和操作位置。',
            vulnerability_type='path_traversal', primary_location=dict(path=PATH, line=4),
            evidence=PATH+':1-4', dangerous_operation='readfile using request input',
            dataflow=finding()['dataflow'])
        if key == 'bad-citation':
            claim['dataflow'][0]['evidence'] = dict(path='src/auth.php', start_line=2, end_line=2)
            rejected_payloads.append(copy.deepcopy(claim))
        return worker_outcome('achieved', finding=claim, seen=SEEN)

    monkeypatch.setattr(worker_module, 'plan_audit_frontier', planner)
    monkeypatch.setattr(worker_module, 'pursue_planner_task', source)
    asyncio.run(make_worker(store, repo)._execute(run))
    final = store.get_run(run['id'])
    assert final['status'] == 'inconclusive', final.get('error')
    assert 'valid-peer' in calls and 'after-workers' in calls
    tasks = {t['task_key']: t for t in store.list_tasks(run['id'])}
    assert tasks['bad-citation']['state'] == 'blocked'
    assert tasks['valid-peer']['state'] == 'completed'
    rejected = store.list_task_attempts(tasks['bad-citation']['id'])[0]
    assert rejected['outcome'] == 'blocked'
    assert rejected['result']['terminal_reason'] == 'evidence_rejected'
    assert rejected['result']['rejected_assessment']['findings'] == rejected_payloads
    assert len(store.list_findings(run['id'])) == 1
    events = store.list_events(run['id'], limit=1000)
    assert any(e['kind'] == 'worker_assessment_rejected' for e in events)
    assert not any(e['kind'] == 'run_failed' for e in events)
