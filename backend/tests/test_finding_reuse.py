"""Source-backed delta publication, live lookup and independent novelty review."""
import asyncio
import copy
import json

import pytest
from pydantic import ValidationError

from audit import agent, finding_reuse
from audit.final_review import canonical_groups
from audit.project_findings import exact_run_identity, pick_run_merge_candidate
from audit.role_policy import WorkerAssessmentError
from audit.runtime import AgentPolicy
from audit.schemas import GoalAssessment
from audit.worker import _normalise_task_findings
from tests.code_model import ModelFactory, code, transcript
from tests.test_bounded_investigation import bounded  # noqa: F401
from tests.test_worker_evidence_roles import owned, exhaustive, hosted, state  # noqa: F401
from tests.test_worker_strategies import CONFIG, Repository, UNIT, finding
from tests.test_audit_directions import commit
from tests.test_goal_tasks import proposal, _conclusion_finding

TASK = dict(workflow_policy='discovery_first', investigation_policy='bounded-v1', require_poc=False)


def known(ident='existing-finding', **changes):
    return dict(id=ident, run_id='run', revision=1, finding_kind='vulnerability', validation_state='candidate',
                disposition='open', verification_status='unverified', **{**finding(), **changes})


def reference(item=None, **changes):
    item = item or known()
    return dict(finding_id=item['id'], revision=int(item.get('revision') or 1),
                evidence=[dict(path=item['primary_location']['path'], start_line=item['primary_location']['line'], end_line=item['primary_location']['line'])],
                rationale='本次实际读取该根因和输入传播，作为已有结论的补充来源证据。', **changes)


def assessment(ref=None):
    return dict(outcome='achieved', summary='已核对相同源码根因，引用现有漏洞。',
                reasoning='当前只是补充证据，不产生另一条独立漏洞。', finding_references=[ref or reference()])


def persisted(bounded):
    store, repo, run = bounded
    value = {**_conclusion_finding(run), 'primary_location': dict(path='public/index.php', line=4), 'vulnerability_type':'sqli'}
    store.add_finding(value)
    return store, repo, run, store.get_finding(value['id'])


def test_short_reference_satisfies_worker_payload_without_creating_a_second_claim():
    result = GoalAssessment.model_validate(assessment())
    assert result.findings == [] and result.finding is None and result.outcome == 'achieved'
    normalized = _normalise_task_findings(dict(outcome='achieved', result={**result.model_dump(), 'observations':[dict(title='已有根因',kind='data_flow')]}))
    assert normalized['outcome'] == 'achieved'
    with pytest.raises(ValidationError, match='observations cannot satisfy'):
        GoalAssessment.model_validate({**assessment(), 'finding_references': []})
    with pytest.raises(ValidationError, match='require achieved'):
        GoalAssessment.model_validate({**assessment(), 'outcome':'no_evidence'})


def test_registry_is_run_wide_compact_and_keeps_ambiguous_locations_separate():
    first = known(title='secret full report body', cvss_input={'large':'x'*10000}, poc={'script':'x'*10000})
    other = known('other', primary_location=dict(path='src/b.php', line=3))
    same = known('same-coordinate')
    alias = {**known('duplicate-alias'), 'disposition':'duplicate'}
    foreign = {**known('foreign'), 'run_id':'another-run'}
    index = finding_reuse.registry([first, other, same, alias, foreign], 'run')
    assert {r['finding_id'] for r in index['items']} == {'existing-finding','other','same-coordinate'}
    assert 'secret full report body' not in json.dumps(index) and 'cvss_input' not in json.dumps(index)
    page = finding_reuse.registry([first,other,same], 'run', path='src/a.php', limit=1)
    assert page['total'] == 2 and page['next_offset'] == 1
    following = finding_reuse.registry([first,other,same], 'run', path='src/a.php', limit=1, offset=page['next_offset'])
    assert page['items'][0]['finding_id'] != following['items'][0]['finding_id']


@pytest.mark.parametrize('change,spans', [
    ({'revision':2}, [('src/a.php',3,3)]),
    ({'finding_id':'foreign'}, [('src/a.php',3,3)]),
    ({}, [('src/a.php',1,1)]),
    ({'evidence':[dict(path='src/a.php', start_line=1,end_line=1)]}, [('src/a.php',1,3)]),
])
def test_reference_requires_current_identity_actual_reads_and_root_coverage(change, spans):
    with pytest.raises(ValueError):
        finding_reuse.validate_references(TASK, [{**reference(), **change}], [known()], spans, run_id='run')


def test_reference_cannot_cross_a_withdrawal_or_dynamic_counterexample():
    for changes in [dict(disposition='duplicate'),dict(disposition='retracted'),dict(verification_status='rejected')]:
        with pytest.raises(ValueError, match='仍有效'):
            finding_reuse.validate_references(TASK,[reference()], [{**known(), **changes}], [('src/a.php',3,3)],run_id='run')
    with pytest.raises(ValueError, match='不支持'):
        finding_reuse.validate_references({},[reference()],[known()],[('src/a.php',3,3)],run_id='run')


def test_coordinate_collision_requires_an_explicit_difference_but_never_auto_merges():
    first, incoming = known(), finding(title='另一个参数造成相同位置的不同输出路径')
    with pytest.raises(ValueError, match='finding_references'):
        finding_reuse.validate_novelty(TASK,[incoming],[first],run_id='run')
    incoming.update(related_finding_id=first['id'],novelty_reason='该处另一输入参数经过独立输出分支，修复原分支并不能修复本项。')
    finding_reuse.validate_novelty(TASK,[incoming],[first],run_id='run')
    finding_reuse.validate_novelty(TASK,[finding(primary_location=dict(path='src/a.php',line=2))],[first],run_id='run')
    with pytest.raises(ValueError, match='同一批'):
        finding_reuse.validate_novelty(TASK,[finding(),finding(title='同一根因仅改标题')],[],run_id='run')
    distinct = {**first, 'novelty': {'related_finding_id':first['id'], 'rationale':incoming['novelty_reason']}}
    assert exact_run_identity(first) != exact_run_identity(distinct)
    assert pick_run_merge_candidate(distinct,[first]) is None
    assert pick_run_merge_candidate(first,[distinct]) is None


def test_exact_batch_repeat_collapses_without_breaking_explicit_finding_indices():
    value=dict(outcome='achieved', summary='保留实际风险证据', reasoning='同一输入在该处输出。',findings=[finding(),finding()])
    assert len(GoalAssessment.model_validate(value).findings) == 1
    value['observations']=[dict(title='明确关联第二项',kind='data_flow',summary='这是第二项输出操作的来源观察。',evidence='src/a.php:3-3',finding_index=1)]
    assert len(GoalAssessment.model_validate(value).findings) == 2


def test_live_worker_can_publish_only_a_reference_and_sees_new_peer_findings(monkeypatch):
    current = []
    def response(messages):
        current.append(known())
        return json.dumps(assessment(), ensure_ascii=False)
    factory=ModelFactory([response])
    monkeypatch.setattr(agent,'build_code_model',factory)
    outcome=asyncio.run(agent.pursue_task_work(repository=Repository(),snapshot_id='snapshot',snapshot_name='demo.zip',
        unit=UNIT,task=TASK,attempt=1,current_run_id='run',current_findings=[],current_findings_reader=lambda:current,
        config=CONFIG,budgets=dict(responses=3,tools=0,seconds=10),policy=AgentPolicy(request_seconds=1,worker_explore_responses=0)))
    assert outcome['outcome']=='achieved',outcome
    assert outcome['result']['findings']==[] and len(outcome['result']['finding_references'])==1
    assert outcome['usage']['requests']==1 and outcome['usage']['tool_calls']==0


def test_reference_correction_uses_a_short_reference_example_instead_of_a_full_report(monkeypatch):
    bad=assessment()
    bad['observations']=[dict(title='同一根因补核',kind='data_flow',summary='本次读取重复支持已有输出根因。',
        evidence='src/a.php:3-3',finding_index=0,follow_up=False)]
    factory=ModelFactory([json.dumps(bad,ensure_ascii=False),json.dumps(assessment(),ensure_ascii=False)])
    monkeypatch.setattr(agent,'build_code_model',factory)
    result=asyncio.run(agent.pursue_task_work(repository=Repository(),snapshot_id='snapshot',snapshot_name='demo.zip',
        unit=UNIT,task=TASK,attempt=1,current_run_id='run',current_findings=[known()],
        config=CONFIG,budgets=dict(responses=3,tools=0,seconds=10),policy=AgentPolicy(request_seconds=1,worker_explore_responses=0)))
    assert result['outcome']=='achieved' and result['usage']['requests']==2
    correction=transcript([factory.built().requests[1][-1]])
    assert 'finding_references' in correction and 'findings 为空' in correction
    assert 'dataflow' not in correction and 'cvss_input' not in correction


def test_reference_commit_survives_to_final_review_without_new_finding_or_poc(bounded):
    store,repo,run,item=persisted(bounded)
    commit(store,run,tasks=[proposal('corroborate-existing')])
    task=store.claim_ready_task(run['id'],'worker')
    ref=reference(item)
    before=copy.deepcopy(store.get_finding(item['id']))
    resolved=store.resolve_task_attempt(task['id'],'worker',outcome='achieved',result=assessment(ref),usage={},
        seen=[dict(path='public/index.php',start_line=1,end_line=4)],terminal_reason='completed')
    assert resolved['state']=='completed' and resolved['result']['host_progress']['new_conclusions']==0
    assert len(store.list_findings(run['id']))==1 and store.get_finding(item['id'])==before
    batch=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    root=next(i for i in batch['items'] if i.get('finding_id')==item['id'])
    corroboration=root['payload']['worker_references'][0]
    assert corroboration['evidence_complete'] and corroboration['source_field']=='source_excerpts'
    assert len(root['source_excerpts'])==1  # Reused root source is sent only once.
    assert corroboration['finding_id']==item['id'] and corroboration['task_key']=='corroborate-existing'
    assert store._row('SELECT COUNT(*) FROM poc_verification_jobs WHERE run_id=?',(run['id'],))[0]==0
    assert store.has_event(run['id'],'worker_findings_reused')
    # Regression: reference-aware revisions used to be computed only by batch
    # creation, so a committed accept silently disappeared during report attachment.
    from tests.test_host_queue import submit
    submit(store, run, batch)
    attached, _ = canonical_groups(store.attach_final_decisions(run['id'], store.list_findings(run['id'])))
    assert attached[0]['final_disposition'] == 'accepted'
    assert attached[0]['final_batch_review']['revision'] == root['revision']
    assert not any(i.get('finding_id') == item['id'] for b in store.review_batches_pending(run['id'], 'final', repo) for i in b)


def test_host_rechecks_reference_version_inside_the_commit_transaction(bounded):
    store,repo,run,item=persisted(bounded)
    commit(store,run,tasks=[proposal('stale-reference')])
    task=store.claim_ready_task(run['id'],'worker')
    ref=reference(item)
    store._write('UPDATE findings SET revision=revision+1 WHERE id=?',(item['id'],))
    with pytest.raises(WorkerAssessmentError,match='revision'):
        store.resolve_task_attempt(task['id'],'worker',outcome='achieved',result=assessment(ref),usage={},
            seen=[dict(path='public/index.php',start_line=1,end_line=4)],terminal_reason='completed')
    assert store.get_planner_task(task['id'])['state']=='running'
    assert not store.has_event(run['id'],'worker_findings_reused')


def test_direct_commit_cannot_relabel_existing_vulnerability_as_no_evidence(bounded):
    store,repo,run,item=persisted(bounded)
    commit(store,run,tasks=[proposal('no-negative-reference')])
    task=store.claim_ready_task(run['id'],'worker')
    with pytest.raises(WorkerAssessmentError,match='no_evidence'):
        store.resolve_task_attempt(task['id'],'worker',outcome='no_evidence',result=assessment(reference(item)),usage={},
            seen=[dict(path='public/index.php',start_line=1,end_line=4)],terminal_reason='completed')
    assert store.get_planner_task(task['id'])['state']=='running'


def test_live_schema_advertises_deltas_without_a_second_singular_finding():
    schema=agent._worker_publication_schema(2,task=TASK)
    assert 'finding_references' in schema['properties'] and 'finding' not in schema['properties']
    assert 'novelty_reason' in schema['$defs']['TaskFinding']['properties']
    legacy=agent._worker_publication_schema(2,task={})
    assert 'finding_references' not in legacy['properties']
    assert 'novelty_reason' not in legacy['$defs']['TaskFinding']['properties']


def test_supported_candidate_can_bind_a_validated_reference_and_preserves_other_pending_work():
    from audit.role_policy import validate_assessment, POLICY
    from tests.test_worker_evidence_roles import candidate
    target=known(primary_location=dict(path='public/index.php',line=4))
    value=assessment(reference(target))
    value['candidate_updates']=[candidate(status='supported', finding_id=target['id'])]
    value['candidate_updates'][0]['missing_context']=[]
    pending={**candidate(), 'candidate_id':'another-root', 'primary_location':dict(path='public/index.php',line=2)}
    task={**TASK,'role_policy':POLICY}
    journal=validate_assessment(task,value,[dict(path='public/index.php',start_line=1,end_line=4)],
        {'public/index.php':4},previous=[pending],known_findings=[target])
    assert {c['candidate_id']:c['status'] for c in journal}=={'another-root':'pending','query-path':'supported'}
    value['finding_references']=[]
    with pytest.raises(ValueError,match='实际发布的 finding'):
        validate_assessment(task,value,[dict(path='public/index.php',start_line=1,end_line=4)],
            {'public/index.php':4},known_findings=[target])


def test_lookup_is_live_across_identical_queries_and_uses_no_extra_model_judge(monkeypatch):
    current=[]
    def second(_messages):
        current.append(known())
        return code("print(lookup_findings(path='src/a.php'))\nfinal_answer(" + repr(assessment()) + ")")
    factory=ModelFactory([code("print(lookup_findings(path='src/a.php'))"),second])
    monkeypatch.setattr(agent,'build_code_model',factory)
    events=[]
    result=asyncio.run(agent.pursue_task_work(repository=Repository(),snapshot_id='snapshot',snapshot_name='demo.zip',
        unit=UNIT,task=TASK,attempt=1,current_run_id='run',current_findings_reader=lambda:current,
        initial_excerpts=[dict(path=UNIT['file_path'],lines=UNIT['cleaned_lines'])],
        config=CONFIG,budgets=dict(responses=6,tools=4,seconds=10),
        policy=AgentPolicy(request_seconds=1,worker_explore_responses=3),on_event=events.append))
    assert result['outcome']=='achieved',result
    lookups=[e for e in events if e.get('kind')=='tool_result' and e.get('tool')=='lookup_findings']
    assert len(lookups)==2 and not any(e.get('cached') for e in lookups)
    assert result['usage']['requests']==2
    assert result['result']['finding_references'][0]['finding_id']=='existing-finding'


def test_explicit_distinction_survives_project_and_run_dedup_for_independent_review(bounded):
    from tests.test_project_findings import _project
    from tests.test_goal_tasks import make_worker
    store,repo,run,first=persisted(bounded)
    project=_project(store)
    store._write('UPDATE runs SET project_id=? WHERE id=?',(project['id'],run['id']))
    worker=make_worker(store,repo)
    prepared=dict(record=first,candidate=True,vulnerability=True,anchor={'file_path':'public/index.php','symbol':'<project>'})
    initial=worker._merge_project_finding(run['id'],first['id'],prepared)
    second={**_conclusion_finding(run,'distinct-finding'),'unit_id':'distinct-unit',
        'vulnerability_type':'sqli','primary_location':dict(path='public/index.php',line=4),
        'novelty':dict(related_finding_id=first['id'],rationale='另一个输入参数进入同一行的独立查询操作，修复第一处输入不能解除本项。')}
    store.add_finding(second)
    proposed=worker._merge_project_finding(run['id'],second['id'],{**prepared,'record':second})
    assert initial['project_finding_id']!=proposed['project_finding_id']
    saved=store.get_finding(second['id'])
    assert saved['novelty']==second['novelty'] and saved['disposition']=='open'
    entries,_=canonical_groups(store.list_findings(run['id']))
    assert len(entries)==2 and all(e['final_disposition']!='accepted' for e in entries)
    assert any(e['frozen_claim'].get('novelty') for e in entries)


def test_continuation_remaps_reference_ids_without_creating_findings(bounded):
    from tests.test_run_continuations import finish, request
    store,repo,run,item=persisted(bounded)
    commit(store,run,tasks=[proposal('reuse-before-continuation')])
    task=store.claim_ready_task(run['id'],'worker')
    store.resolve_task_attempt(task['id'],'worker',outcome='achieved',result=assessment(reference(item)),usage={},
        seen=[dict(path='public/index.php',start_line=1,end_line=4)],terminal_reason='completed')
    finish(store,run)
    frozen=store.frozen_report(run['id'])['input_json']
    child=store.create_continuation(run['id'],request(mode='audit',finding_ids=[]))
    cloned=store.list_findings(child['id'])
    assert len(cloned)==1 and cloned[0]['id']!=item['id']
    task_copy=store.list_tasks(child['id'])[0]
    assert task_copy['result']['finding_references'][0]['finding_id']==cloned[0]['id']
    assert store.frozen_report(run['id'])['input_json']==frozen
