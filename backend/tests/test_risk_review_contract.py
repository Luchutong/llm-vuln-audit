"""Risk outcomes and target relation are independent; a bad peer cannot burn a group."""
import copy

import pytest
from jsonschema import Draft202012Validator

from audit.capability import POLICY, validate_focus
from audit.runtime import StopAudit
from audit.schemas import PlannerDecision
from audit.submission import bind_review_submission, review_contract, review_schema
from audit.structured_output import strict_schema
from tests.test_host_queue import hosted  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_review_closure_repair import risk_batch


def batch():
    return dict(id='batch',phase='final',items=[dict(kind='risk',item_id='risk-a',revision='rev',
        payload=dict(evidence=[dict(path='entry.php',range=dict(start=1,end=4))]),
        focus_target_refs=[dict(item_id='canonical',finding_id='finding')])])


def payload(outcome='supported',relation='relevant'):
    return dict(basis_summary='逐项独立检查实际风险和目标关系。',review_decisions=[dict(decision='resolve',
        rationale='本项请求参数进入实际操作，已检查当前有效结论。',risk_outcome=outcome,finding_ids=['finding'],
        focus=dict(objective_ref='objective-main',relation=relation,rationale='本项危险操作自身位于本次全量审计范围之内。',
                   evidence=[dict(path='entry.php',start_line=1,end_line=4)]))])


def test_risk_schema_requires_its_own_non_nullable_outcome_and_hides_finding_actions():
    frozen=batch();schema=review_schema(PlannerDecision.model_json_schema(),frozen)
    Draft202012Validator.check_schema(schema);Draft202012Validator.check_schema(strict_schema(schema))
    branch=schema['properties']['review_decisions']['items']['anyOf'][0]
    assert 'risk_outcome' in branch['required']
    assert set(branch['properties'])=={'item_id','revision','decision','rationale','focus','risk_outcome','finding_ids'}
    assert branch['properties']['decision']['enum']==['resolve','needs_evidence','skip']
    value=payload();bound=bind_review_submission(value,frozen)
    Draft202012Validator(schema).validate(bound)
    contract=review_contract(frozen)
    assert {'risk_outcome','finding_ids'}<=set(contract['field_hierarchy']['review_decisions[]'])
    assert '不等于' in contract['items'][0]['focus_relation_notice']
    value['review_decisions'][0].pop('risk_outcome')
    with pytest.raises(ValueError,match=r'review_decisions\[risk-a\].risk_outcome'):
        bind_review_submission(value,frozen)


@pytest.mark.parametrize('outcome',['supported','no_evidence','not_applicable'])
def test_unresolved_relation_cannot_be_advertised_as_a_settled_risk(outcome):
    frozen=batch();schema=review_schema(PlannerDecision.model_json_schema(),frozen)
    bound=bind_review_submission(payload(outcome,'unresolved'),frozen)
    assert not Draft202012Validator(schema).is_valid(bound)
    bound['review_decisions'][0]['risk_outcome']='pending'
    assert Draft202012Validator(schema).is_valid(bound)


def test_supporting_requires_targets_and_chain_even_if_the_risk_is_supported():
    frozen=batch();schema=review_schema(PlannerDecision.model_json_schema(),frozen)
    bound=bind_review_submission(payload(relation='supporting'),frozen)
    validator=Draft202012Validator(schema)
    assert not validator.is_valid(bound)
    focus=bound['review_decisions'][0]['focus'];focus['supports']=['canonical']
    focus['chain']=[dict(kind=kind,evidence=dict(path='entry.php',start_line=line,end_line=line),
        explanation='实际读取的输入或敏感操作节点。') for kind,line in [('input',1),('sink',4)]]
    assert validator.is_valid(bound)
    validate_focus(dict(task_spec=dict(capability_policy=POLICY)),focus,
        claim=dict(evidence=[dict(path='entry.php',start_line=1,end_line=4)]),known_ids=['canonical'])
    focus['chain'][1]['kind']='input'
    with pytest.raises(ValueError,match='input→sink'):
        validate_focus(dict(task_spec=dict(capability_policy=POLICY)),focus,
            claim=dict(evidence=[dict(path='entry.php',start_line=1,end_line=4)]),known_ids=['canonical'])


def test_strict_provider_empty_reference_field_preserves_explicit_coordinates():
    value=payload();value['review_decisions'][0]['focus']['evidence_refs']=[]
    bound=bind_review_submission(value,batch())
    assert bound['review_decisions'][0]['focus']['evidence']==value['review_decisions'][0]['focus']['evidence']


def test_first_risk_rejection_isolates_lease_without_renewing_any_item_allowance(hosted,monkeypatch):
    store,repo,run,frozen,_,_=risk_batch(hosted)
    risk=next(i for i in frozen['items'] if i['kind']=='risk')
    peer=copy.deepcopy(risk);peer['item_id']='risk-peer'
    items=[risk,peer]
    import json
    store._write('UPDATE audit_review_batches SET items=? WHERE id=?',(json.dumps(items),frozen['id']))
    monkeypatch.setattr(store,'_review_candidates',lambda *_:copy.deepcopy(items))
    store.reserve_review_publication(run['id'],frozen['id'])
    assert store.active_review_batch(run['id']) is not None  # Never split before reading a response.
    with pytest.raises(StopAudit) as split:
        store.reject_review_publication(run['id'],frozen['id'],ValueError(f"review_decisions[{risk['item_id']}].focus：缺少真实依赖链"))
    assert split.value.reason=='review_batch_split'
    assert store.active_review_batch(run['id']) is None
    assert store.list_review_batches(run['id'])[-1]['status']=='split'
    ledger=store.review_allowances(run['id'],'final')
    assert all(v['publications']==1 for v in ledger.values())
    assert ledger[(peer['item_id'],peer['revision'])]['errors']=={}
    groups=store.review_batches_pending(run['id'],'final')
    assert len(groups)==2 and all(len(g)==1 for g in groups)
    single=store.prepare_review_batch(run['id'],'final',run['execution_epoch'],repo)
    store.reserve_review_publication(run['id'],single['id'])
    selected=single['items'][0]
    assert store.review_allowances(run['id'],'final')[(selected['item_id'],selected['revision'])]['publications']==2
    assert sorted(v['publications'] for v in store.review_allowances(run['id'],'final').values())==[1,2]


@pytest.mark.parametrize('malformed',[False,True])
def test_publication_stops_after_one_group_refusal_instead_of_reasking_healthy_peers(hosted,malformed):
    import asyncio
    import json
    from audit.structured_output import drive_structured_phase
    from tests.code_model import Host,Phase,ScriptedCodeModel
    store,_,run,frozen,_,_=risk_batch(hosted)
    item=next(i for i in frozen['items'] if i['kind']=='risk')
    peer=copy.deepcopy(item);peer['item_id']='risk-peer'
    frozen['items']=[item,peer]
    store._write('UPDATE audit_review_batches SET items=? WHERE id=?',(json.dumps(frozen['items']),frozen['id']))
    async def play():
        host=Host();gate=Phase(host,output_model=PlannerDecision,phase='planner_publish').gate()
        gate.normalize_payload=lambda value:bind_review_submission(value,frozen)
        gate.publication_start=lambda:store.reserve_review_publication(run['id'],frozen['id'])
        gate.publication_error=lambda error,value:store.reject_review_publication(run['id'],frozen['id'],error,value)
        value=dict(basis_summary='实际判读结果，风险字段需要纠正。',review_decisions=[dict(decision='needs_evidence',rationale='保留本项尚待核对的真实源码缺口。') for _ in frozen['items']])
        response='{"unfinished":' if malformed else json.dumps(value,ensure_ascii=False)
        model=ScriptedCodeModel([response],gate=gate)
        with pytest.raises(StopAudit) as failure:
            await drive_structured_phase(model,gate,'JSON','当前风险批次',max_steps=3)
        assert failure.value.reason=='review_batch_split'
        assert len(model.params)==1
    asyncio.run(play())
    assert store.active_review_batch(run['id']) is None
    assert all(v['publications']==1 for v in store.review_allowances(run['id'],'final').values())
