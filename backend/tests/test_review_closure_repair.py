"""November retest review failures: union citations, owned refs and paused checkpoints."""
import copy
import json

import pytest

from audit.capability import POLICY, focus_evidence_ranges, validate_focus
from audit.schemas import PlannerDecision
from audit.submission import bind_review_submission, focus_references, review_schema, review_contract
from tests.test_host_queue import hosted, add_claim, submit  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_run_continuations import request, finish


RUN = {'task_spec': {'capability_policy': POLICY}}


def focus(refs, **changes):
    return dict(objective_ref='objective-main', relation='relevant',
                rationale='已独立核对实际请求输入与敏感操作，确认属于本次审计的业务范围。', evidence=refs) | changes


def ref(start, end=None, path='src/entry.php'):
    return dict(path=path, start_line=start, end_line=start if end is None else end)


def test_contiguous_claim_citations_accept_the_same_exact_union():
    claim = {'evidence': [ref(2), ref(3), ref(4), ref(5)]}
    assert focus_evidence_ranges(claim) == [ref(2,5)]
    validate_focus(RUN, focus([ref(2,5)]), claim=claim)
    validate_focus(RUN, focus([ref(3,4)]), claim=claim)


@pytest.mark.parametrize('evidence', [[ref(2,5)], [ref(1,3)], [ref(3,6)], [ref(2,3,'peer.php')]])
def test_union_never_bridges_unread_gaps_or_other_claims(evidence):
    with pytest.raises(ValueError, match='允许的连续区间'):
        validate_focus(RUN, focus(evidence), claim={'evidence':[ref(2,3),ref(5)]})


def test_supporting_chain_uses_the_identical_no_gap_union():
    claim = {'evidence':[ref(2),ref(3),ref(5)]}
    value=focus([ref(2,3)],relation='supporting',supports=['target'],chain=[
        dict(kind='input',evidence=ref(2,3)),dict(kind='sink',evidence=ref(5))])
    validate_focus(RUN,value,claim=claim,known_ids=['target'])
    value['chain'][1]['evidence']=ref(3,5)
    with pytest.raises(ValueError, match='依赖链'):
        validate_focus(RUN,value,claim=claim,known_ids=['target'])


def batch():
    return dict(id='review-batch',phase='final',items=[
        dict(item_id='claim',revision='v1',kind='finding',payload={'evidence':[ref(2),ref(3)]})])


def test_review_refs_bind_only_transport_while_preserving_independent_judgment():
    frozen=batch();refs=focus_references(frozen['items'][0]);assert len(refs)==1
    payload=dict(basis_summary='独立判读',review_decisions=[dict(decision='accept',rationale='已读取实际源码，链路与结论一致。',
        focus={k:v for k,v in focus([]).items() if k!='evidence'} | {'evidence_refs':[refs[0]['reference_id']]})])
    result=bind_review_submission(payload,frozen)
    assert result['review_decisions'][0]['focus']['evidence']==[ref(2,3)]
    assert 'evidence_refs' not in result['review_decisions'][0]['focus']
    assert result['review_decisions'][0]['decision']=='accept'
    assert payload['review_decisions'][0]['focus']['evidence_refs']==[refs[0]['reference_id']]
    PlannerDecision.model_validate(result)
    assert review_contract(frozen)['items'][0]['focus_evidence_refs']==refs


@pytest.mark.parametrize('change', ['version','owner','explicit_conflict'])
def test_cross_version_or_peer_focus_ids_cannot_be_rebound(change):
    frozen=batch();old=focus_references(frozen['items'][0])[0]['reference_id']
    payload=dict(review_decisions=[dict(decision='needs_evidence',focus=dict(evidence_refs=[old]))])
    if change=='version':frozen['items'][0]['revision']='v2'
    elif change=='owner':frozen['items'][0]['item_id']='peer'
    else:payload['review_decisions'][0]['focus']['evidence']=[ref(1,5)]
    with pytest.raises(ValueError):bind_review_submission(payload,frozen)


def test_paged_coordinates_keep_refs_and_schema_binds_the_current_item():
    frozen=batch();item=frozen['items'][0]
    full=focus_references(item)
    item['reference_coordinates']=dict(evidence=copy.deepcopy(item['payload']['evidence']),peers=[])
    item['payload'].pop('evidence')
    assert focus_references(item)==full
    schema=review_schema(PlannerDecision.model_json_schema(),frozen)
    decision=schema['properties']['review_decisions']['items']['anyOf'][0]
    spec=decision['properties']['focus']['anyOf'][0]['properties']
    assert spec['evidence_refs']['items']['enum']==[full[0]['reference_id']]
    # Compact schemas keep typed legacy coordinates; the authoritative shared
    # gate enforces the same per-item range rather than repeating it in schema.
    assert '$ref' in spec['evidence']['items']
    claim={'evidence':item['reference_coordinates']['evidence']}
    validate_focus(RUN,focus([ref(2,3)]),claim=claim)
    with pytest.raises(ValueError,match='允许的连续区间'):
        validate_focus(RUN,focus([ref(1,3)]),claim=claim)


def pause(store, run):
    store.request_pause(run['id'])
    assert store.get_run(run['id'])['status']=='paused'
    store.quiesce_execution(run['id'])


def test_quiescent_paused_checkpoint_can_review_without_mutating_parent(hosted):
    store, repo, run=hosted
    add_claim(store,run,1,verified=True)
    pause(store,run)
    parent=store.get_run(run['id']);before_findings=store.list_findings(run['id'])
    options=store.continuation_options(run['id'])
    assert options['available'] and options['review_only']
    child=store.create_continuation(run['id'],request(mode='review',structured_output='json_object',run_limits=dict(responses=176,tools=0,seconds=3600)),
        model_profile=dict(model='offline-test',base_url='https://example.invalid'))
    assert child['model_profile']['structured_output']=='json_object'
    assert child['poc_policy']['mode']=='off' and not child['poc_policy']['required']
    assert child['task_spec']['continuation']['parent_checkpoint']['purpose']=='review_only'
    assert len(store.list_findings(child['id']))==1
    assert not store.resume_run(run['id'])
    assert store.get_run(run['id'])['status']=='paused'
    assert store.get_run(run['id'])['execution_summary']['run_usage']==parent['execution_summary']['run_usage']
    assert store.list_findings(run['id'])==before_findings
    assert store.frozen_report(run['id']) is None


@pytest.mark.parametrize('mode',['audit','poc_review'])
def test_paused_checkpoint_cannot_start_source_or_poc_in_parallel(hosted,mode):
    store, _, run=hosted;add_claim(store,run,1);pause(store,run)
    with pytest.raises(ValueError,match='暂停记录只允许'):
        store.create_continuation(run['id'],request(mode=mode))
    assert store._row('SELECT COUNT(*) FROM runs')[0]==1


def test_inflight_pause_cannot_clone_until_ownership_quiesces(hosted):
    store, _, run=hosted;add_claim(store,run,1);store.request_pause(run['id'])
    assert not store.continuation_options(run['id'])['available']


def test_restart_preserves_a_durable_quiescent_pause_and_review_ownership(hosted):
    store, _, run=hosted;add_claim(store,run,1);pause(store,run)
    before=store.get_run(run['id'])['task_spec']
    assert store.interrupt_stale_runs()==0
    assert store.get_run(run['id'])['status']=='paused'
    assert store.get_run(run['id'])['task_spec']==before
    assert store.continuation_options(run['id'])['review_only']


def test_candidate_generation_never_expands_the_user_interface_execution_summary(hosted,monkeypatch):
    store, _, run=hosted
    for n in range(4):add_claim(store,run,n)
    def unavailable(_id):raise AssertionError('Heavy dashboard summary must not be used for review fact generation')
    monkeypatch.setattr(store,'execution_summary',unavailable)
    assert len([i for i in store._review_candidates(run['id'],'final') if i['kind']=='finding'])==4


def test_native_format_survives_sanitizing_frozen_profiles_and_rejects_unknown_modes():
    from audit.db import _model_profile_snapshot
    profile=dict(profile_id='current',model='model',base_url='https://model.invalid',structured_output='json_object',api_key='private')
    public=_model_profile_snapshot(profile)
    assert public['structured_output']=='json_object' and 'api_key' not in public
    assert 'structured_output' not in _model_profile_snapshot({**profile,'structured_output':'unsupported'})


@pytest.mark.parametrize('same_provider',[True,False])
def test_next_continuation_inherits_proven_native_mode_only_for_identical_provider(hosted,same_provider):
    store, _, run=hosted
    profile=dict(profile_id='current',model='model',base_url='https://model.invalid',structured_output='json_object')
    store._write('UPDATE runs SET model_profile=? WHERE id=?',(json.dumps(profile),run['id']))
    finish(store,run)
    selected={k:v for k,v in profile.items() if k!='structured_output'}
    if not same_provider:selected['base_url']='https://another.invalid'
    child=store.create_continuation(run['id'],request(mode='review'),model_profile=selected)
    assert (child['model_profile'].get('structured_output')=='json_object') is same_provider


def test_support_aliases_bind_only_unambiguous_current_item_targets():
    frozen=batch();item=frozen['items'][0]
    item['focus_target_refs']=[dict(item_id='canonical',finding_id='run-finding')]
    value=dict(review_decisions=[dict(decision='needs_evidence',focus=focus([],relation='supporting',supports=['run-finding','unknown'],chain=[]))])
    bound=bind_review_submission(value,frozen)['review_decisions'][0]['focus']
    assert bound['supports']==['canonical','unknown']
    assert bound['chain']==[] and bound['relation']=='supporting'
    assert value['review_decisions'][0]['focus']['supports']==['run-finding','unknown']
    assert review_contract(frozen)['items'][0]['focus_target_refs']==item['focus_target_refs']
    item['focus_target_refs'].append(dict(item_id='different',finding_id='run-finding'))
    with pytest.raises(ValueError,match='别名不唯一'):bind_review_submission(value,frozen)
    value['review_decisions'][0]['focus']['supports']='run-finding'
    with pytest.raises(ValueError,match='ID 列表'):bind_review_submission(value,frozen)


def risk_batch(hosted):
    from audit.capability import freeze_focus
    from audit.risk_coverage import freeze
    from tests.test_goal_tasks import proposal
    store,repo,run=hosted
    spec={**run['task_spec'],'capability_policy':POLICY,'exploration_policy':'exhaustive-v1','focus_scope':'all'}
    spec.update(audit_focus=freeze_focus(spec),risk_coverage_policy='bounded-v1',
                risk_obligation_set=freeze(store.get_project_map(run['id']),spec,run['snapshot_id']))
    store._write('UPDATE runs SET task_spec=? WHERE id=?',(json.dumps(spec),run['id']))
    run=store.get_run(run['id']);operation=spec['risk_obligation_set']['items'][0]
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='读取实际风险操作与上下文',tasks=[proposal('risk-read')])
    task=store.claim_ready_task(run['id'],'worker')
    store.resolve_task_attempt(task['id'],'worker',outcome='no_evidence',result=dict(outcome='no_evidence',summary='已读取实际敏感操作与鉴权上下文。',remaining_work=[]),
        usage={},seen=[ref(1,operation['line']+1,operation['path'])],terminal_reason='completed')
    finding=add_claim(store,run,1)
    store._write('UPDATE findings SET primary_location=?,evidence=? WHERE id=?',
        (json.dumps(dict(path=operation['path'],line=operation['line'])),json.dumps([ref(1,operation['line'],operation['path'])]),finding['id']))
    frozen=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    decisions=[]
    for item in frozen['items']:
        value=dict(item_id=item['item_id'],revision=item['revision'],decision='needs_evidence',rationale='保留尚未完成独立判读的真实源码结论。')
        if item['kind']=='risk':
            source=item['payload']['evidence'][0]
            value.update(decision='resolve',risk_outcome='supported',finding_ids=[finding['id']],
                focus=focus([ref(source['range']['start'],source['range']['end'],source['path'])]))
        decisions.append(value)
    return store,repo,run,frozen,decisions,finding


def test_risk_reference_contract_and_rejection_charge_only_the_failing_item(hosted):
    from audit.review_control import error_subjects
    store,repo,run,frozen,decisions,finding=risk_batch(hosted)
    item=next(i for i in frozen['items'] if i['kind']=='risk')
    claim=next(i for i in frozen['items'] if i['kind']=='finding')
    assert item['focus_target_refs']==[dict(item_id=claim['item_id'],finding_id=finding['id'])]
    value=next(d for d in decisions if d['item_id']==item['item_id'])
    value['finding_ids']=['unknown-finding']
    second=copy.deepcopy(item);second['item_id']='risk-other';frozen['items'].append(second)
    store._write('UPDATE audit_review_batches SET items=? WHERE id=?',(json.dumps(frozen['items']),frozen['id']))
    other=copy.deepcopy(value);other['item_id']=second['item_id'];other['finding_ids']=[];decisions.append(other)
    current=store._review_candidates(run['id'],'final')+[second]
    with pytest.raises(ValueError,match='实际危险操作') as failure:
        store.validate_review_decisions(run['id'],frozen,decisions,current_items=current)
    assert error_subjects(failure.value,dict(review_decisions=decisions),frozen['items'])=={
        (item['item_id'],'contract:finding_ids'),(second['item_id'],'contract:finding_ids')}


@pytest.mark.parametrize('change',[None,'stale_revision','changed_fact','legacy_policy'])
@pytest.mark.parametrize('choice',['resolve','skip'])
@pytest.mark.parametrize('mode',['review','audit','poc_review'])
def test_continuation_carries_only_identical_resolved_risk_inputs(hosted,change,choice,mode):
    store,repo,run,frozen,decisions,finding=risk_batch(hosted)
    risk=next(i for i in frozen['items'] if i['kind']=='risk')
    if choice=='skip':
        value=next(d for d in decisions if d['item_id']==risk['item_id'])
        value.update(decision='skip',risk_outcome='no_evidence',finding_ids=[])
        value['focus']['relation']='incidental'
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary='真实风险结论引用完成独立判读。',
        review_batch_id=frozen['id'],review_decisions=decisions)
    if change=='stale_revision':
        store._write("UPDATE audit_review_items SET revision='old' WHERE run_id=? AND item_id=?",(run['id'],risk['item_id']))
    elif change=='changed_fact':
        store._write("UPDATE findings SET title='变化后的风险主张' WHERE id=?",(finding['id'],))
    elif change=='legacy_policy':
        spec=dict(store.get_run(run['id'])['task_spec']);spec.pop('capability_policy')
        store._write('UPDATE runs SET task_spec=? WHERE id=?',(json.dumps(spec),run['id']))
    if mode=='review':pause(store,run)
    else:finish(store,run)
    child=store.create_continuation(run['id'],request(mode=mode))
    rows=store._rows('SELECT decision FROM audit_review_items WHERE run_id=? AND item_id=?',(child['id'],risk['item_id']))
    assert bool(rows) is (change is None)
    if rows:
        decision=json.loads(rows[0]['decision']);copied=store.list_findings(child['id'])[0]
        assert decision['finding_ids']==([copied['id']] if choice=='resolve' else []) and copied['id']!=finding['id']
        assert decision['inherited_from_run_id']==run['id']
        assert store.risk_coverage(child['id'])['by_state']['supported' if choice=='resolve' else 'no_evidence']==1
        store._write("UPDATE findings SET title='继续任务的新事实使原审查失效' WHERE id=?",(copied['id'],))
        pending=store.review_batches_pending(child['id'],'final',repo)
        assert any(item['item_id']==risk['item_id'] for group in pending for item in group)


def test_risk_carry_compares_full_navigation_sets_without_discarding_evidence_order():
    from audit.continuations import risk_input
    value=dict(findings=[dict(finding_id='b',revision=1),dict(finding_id='a',revision=2)],
               tasks=[dict(task_key='b'),dict(task_key='a')],evidence=[ref(1),ref(2)])
    reordered={**value,'findings':list(reversed(value['findings'])),'tasks':list(reversed(value['tasks']))}
    assert risk_input(value)==risk_input(reordered)
    changed=copy.deepcopy(reordered);changed['findings'][0]['revision']+=1
    assert risk_input(value)!=risk_input(changed)
    assert risk_input(value)!=risk_input({**reordered,'evidence':list(reversed(value['evidence']))})
