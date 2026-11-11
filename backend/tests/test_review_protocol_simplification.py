"""Single judgments, shared exact evidence, and one protocol across review gates."""
import asyncio
import copy
import json

import pytest
from jsonschema import Draft202012Validator

from audit import agent
from audit.review_policy import allowed_review_decisions, bind_peer_indices, validate_peer_assessments
from audit.review_prompt import INSTRUCTIONS, encode, review_prompt_data, review_request
from audit.review_store import validate_batch
from audit.runtime import AgentPolicy
from audit.schemas import PlannerDecision
from audit.submission import bind_review_submission, review_contract, review_example, review_schema
from tests.code_model import CONFIG, ModelFactory, transcript
from tests.test_recent_final_review_repair import peer_claims
from tests.test_run_continuations import decisions
from tests.test_host_queue import hosted  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_review_input_repair import read_all


def judgment(peer='peer', relation='distinct'):
    return dict(item_id=peer, relation=relation, rationale='当前输入、操作及利用前提与对照结论不同，逐项依据已明确。')


def test_derive_only_the_redundant_index_and_preserve_the_explicit_judgment():
    raw=[dict(item_id='own',decision='accept',comparison_assessments=[judgment()])]
    saved=copy.deepcopy(raw)
    bound=bind_peer_indices(raw)
    assert bound[0]['distinct_from']==['peer'] and raw==saved
    assert bind_peer_indices(bound)==bound
    current={'own':dict(payload=dict(comparison_candidates=[dict(item_id='peer')]))}
    validate_peer_assessments(bound,current)


@pytest.mark.parametrize('index', [['other'],['peer','other'],[{}],'peer'])
def test_a_conflicting_or_malformed_legacy_index_is_rejected(index):
    with pytest.raises(ValueError,match='distinct_from'):
        bind_peer_indices([dict(item_id='own',distinct_from=index,comparison_assessments=[judgment()])])


@pytest.mark.parametrize('relation',['same_root','unresolved'])
def test_normalization_never_turns_non_distinct_into_acceptance(relation):
    value=bind_peer_indices([dict(item_id='own',decision='accept',comparison_assessments=[judgment(relation=relation)])])
    assert value[0]['distinct_from']==[]
    with pytest.raises(ValueError,match='comparison_assessments'):
        validate_peer_assessments(value,{'own':dict(payload=dict(comparison_candidates=[dict(item_id='peer')]))})


def test_an_index_alone_does_not_invent_a_peer_judgment():
    value=[dict(item_id='own',decision='accept',distinct_from=['peer'])]
    assert bind_peer_indices(value)==value
    with pytest.raises(ValueError,match='comparison_assessments'):
        validate_peer_assessments(value,{'own':dict(payload=dict(comparison_candidates=[dict(item_id='peer')]))})


def test_publication_and_transaction_use_the_same_generated_index(hosted):
    store,repo,run=hosted
    run=peer_claims(store,run,2)
    batch=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    for item in batch['items']:
        read_all(store,repo,run,batch,item)
    values=decisions(batch)
    for item,value in zip(batch['items'],values):
        value['comparison_assessments']=[judgment(p['item_id']) for p in item['payload']['comparison_candidates']]
        value.pop('distinct_from',None)
        # This regression concerns static conclusions, not a fabricated confirmation.
        if item.get('requires_verification_review'):
            value['decision']='needs_evidence'
    raw=dict(basis_summary='基于完整源码逐项保留实际差异与未决观测。',review_decisions=values)
    normalized=bind_review_submission(raw,batch)
    validated=store.validate_review_decisions(run['id'],batch,values)
    assert [v['distinct_from'] for v in validated]==[v['distinct_from'] for v in normalized['review_decisions']]
    plan=store.begin_planner_round(run['id'],store.get_planner_session(run['id'])['session_id'])
    store.finish_planner_round(run['id'],plan['id'],goal_state='continue',basis_summary=raw['basis_summary'],
        review_batch_id=batch['id'],review_decisions=values)
    persisted=store._rows("SELECT decision FROM audit_review_items WHERE run_id=? AND phase='final'",(run['id'],))
    assert all('distinct_from' in json.loads(row[0]) for row in persisted)


@pytest.mark.parametrize('phase,kind,context,allowed',[
    ('integration','finding',{},['retain','needs_evidence','contested','duplicate','withdraw']),
    ('final','finding',{},['accept','needs_evidence','contested','duplicate','withdraw']),
    ('final','direction',{'can_resolve':False},['needs_evidence']),
    ('integration','direction',{'requirement':'required'},['resolve','needs_evidence']),
    ('final','risk',{},['resolve','needs_evidence','skip']),
])
def test_schema_contract_and_transaction_share_legal_actions(phase,kind,context,allowed):
    item=dict(item_id='item',revision='revision',kind=kind,payload=dict(resolution_context=context),
        evidence_complete=True,operation_read=True)
    batch=dict(id='batch',phase=phase,items=[item])
    assert allowed_review_decisions(item,phase)==allowed
    schema=review_schema(PlannerDecision.model_json_schema(),batch)
    assert schema['properties']['review_decisions']['items']['anyOf'][0]['properties']['decision']['enum']==allowed
    assert review_contract(batch)['items'][0]['allowed_decisions']==allowed
    value=dict(item_id='item',revision='revision',decision='needs_evidence',rationale='尚有具体源码事实未获得，保留当前缺口。',risk_outcome='pending')
    validate_batch(batch,[value])
    forbidden=copy.deepcopy(value);forbidden['decision']='invalid'
    with pytest.raises(ValueError):validate_batch(batch,[forbidden])


def source_fixture():
    excerpt=dict(path='entry.php',start_line=1,end_line=2,lines=[dict(number=1,text='<?php '+ 'same_source_'*80),
        dict(number=2,text="query($_GET['q']);")])
    return dict(id='batch',phase='final',items=[dict(item_id=f'claim-{n}',revision='revision',kind='finding',
        payload=dict(summary=f'独立主张 {n}',evidence=[dict(path='entry.php',range=dict(start=1,end=2))]),
        source_excerpts=[copy.deepcopy(excerpt)]) for n in range(4)])


def test_same_source_is_sent_once_with_every_original_claim_and_byte_preserved():
    original=source_fixture();snapshot=copy.deepcopy(original)
    projected=review_prompt_data(original)
    assert original==snapshot and len(projected['shared_source_excerpts'])==1
    assert len(encode(projected).encode())<len(encode(original).encode())
    restored=copy.deepcopy(projected);pool=restored.pop('shared_source_excerpts')
    for item in restored['items']:
        item['source_excerpts']=[pool[key] for key in item.pop('source_excerpt_refs')]
    assert restored==original
    assert review_prompt_data(original)==projected


def test_different_source_bytes_are_never_deduplicated_by_coordinates_alone():
    original=source_fixture()
    original['items'][-1]['source_excerpts'][0]['lines'][-1]['text']='different actual code'
    projected=review_prompt_data(original)
    assert len(projected['shared_source_excerpts'])==2
    refs=[i['source_excerpt_refs'] for i in projected['items']]
    assert refs[0]==refs[1] and refs[-1]!=refs[0]


def test_shared_peer_bodies_keep_every_per_item_candidate_and_rationale():
    original=source_fixture()
    peer=dict(item_id='peer',revision='version',summary='完整的对照主张及证据。'*300,
        evidence=[dict(path='peer.php',start_line=3,end_line=3)],basis='共享路径不是同根因判决。')
    for item in original['items']:
        item['payload']['comparison_candidates']=[copy.deepcopy(peer)]
    projected=review_prompt_data(original)
    assert len(projected['shared_comparison_candidates'])==1
    restored=copy.deepcopy(projected)
    sources=restored.pop('shared_source_excerpts');peers=restored.pop('shared_comparison_candidates')
    for item in restored['items']:
        item['source_excerpts']=[sources[key] for key in item.pop('source_excerpt_refs')]
        payload=item['payload']
        payload['comparison_candidates']=[peers[key] for key in payload.pop('comparison_candidate_refs')]
    assert restored==original


def test_a_peer_with_changed_facts_or_comparison_basis_is_not_reused():
    original=source_fixture()
    for item in original['items']:
        item['payload']['comparison_candidates']=[dict(item_id='peer',summary='完整主张。'*300,basis='同位置待判读')]
    original['items'][-1]['payload']['comparison_candidates'][0]['basis']='另一条引用链，单独待判读'
    projected=review_prompt_data(original)
    assert len(projected['shared_comparison_candidates'])==2


def test_finding_only_validation_does_not_load_unrelated_task_or_direction_history(hosted,monkeypatch):
    from tests.test_host_queue import add_claim
    store,repo,run=hosted
    add_claim(store,run,0)
    batch=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    for item in batch['items']:read_all(store,repo,run,batch,item)
    current=store._review_candidates(run['id'],'final')
    def unrelated(*args,**kwargs):pytest.fail('finding judgment must not hydrate unrelated task/direction history')
    monkeypatch.setattr(store,'list_tasks',unrelated)
    monkeypatch.setattr(store,'_audit_direction_records',unrelated)
    assert store.validate_review_decisions(run['id'],batch,decisions(batch),current_items=current)


def test_small_or_non_repeating_source_does_not_gain_an_extra_envelope():
    for batch in [dict(items=[dict(source_excerpts=[dict(path='a')])]),dict(items=[dict(source_excerpts=[{}])]*2)]:
        assert review_prompt_data(batch)==batch


def test_examples_and_wire_contract_no_longer_require_the_redundant_index():
    batch=source_fixture()
    schema=review_schema(PlannerDecision.model_json_schema(),batch)
    assert all('distinct_from' not in b['properties'] for b in schema['properties']['review_decisions']['items']['anyOf'])
    example=review_example(batch)
    Draft202012Validator(schema).validate(example)
    assert 'distinct_from' not in review_contract(batch)['field_hierarchy']['review_decisions[]']
    request=review_request(dict(objective='检查请求进入查询路径。',success_criteria='保留可核对证据。'),batch,schema)
    assert request.count('same_source_'*80)==1
    assert 'shared_source_excerpts' in request and '完整 JSON 字段契约' in request
    assert INSTRUCTIONS.count('distinct_from')==1


@pytest.mark.parametrize('minimal', [False, True])
def test_real_planner_accepts_explicit_judgments_in_one_request_without_an_index(hosted,monkeypatch,minimal):
    store,repo,run=hosted
    run=peer_claims(store,run,2)
    # Both claims are static here; dynamic observations have separate regression coverage.
    store._write("UPDATE findings SET verification_status='unverified' WHERE run_id=?",(run['id'],))
    batch=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    values=decisions(batch)
    for item,value in zip(batch['items'],values):
        value['comparison_assessments']=[judgment(p['item_id']) for p in item['payload']['comparison_candidates']]
        value.pop('distinct_from',None)
    payload=dict(basis_summary='逐项核对本次输入及操作差异后发布静态判读。',review_decisions=values)
    if minimal:
        payload.update(report='过时的展示散文不能阻断真实审查决定。',next_action=42)
    factory=ModelFactory({'planner_publish':[json.dumps(payload,ensure_ascii=False)]})
    monkeypatch.setattr(agent,'build_code_model',factory)
    context={**store.list_planner_context(run['id'],project_map=store.get_project_map(run['id'])),'review_batch':batch}
    result=asyncio.run(agent.plan_audit_frontier(project_map=store.get_project_map(run['id']),run_context=context,
        task={**run['task_spec'], **(dict(output_policy='audit-evidence-v1') if minimal else {})},round_no=1,config=CONFIG,budgets=dict(responses=3,tools=0,seconds=10),
        policy=AgentPolicy(request_seconds=1),repository=repo,snapshot_id=run['snapshot_id'],
        allowed_paths=set(run['scope']),pins=store,run_id=run['id']))
    assert result['decision'] and result['usage']['requests']==1 and result['usage']['tool_calls']==0,result
    assert all(v['distinct_from'] for v in result['decision']['review_decisions'])
    system=transcript(factory.built().requests[0][:1])
    assert 'claim-000' not in system and 'ledger-0' not in system
