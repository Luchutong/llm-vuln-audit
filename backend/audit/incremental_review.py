"""Reuse exact semantic review facts across a continuation, with explicit provenance."""
import copy
import json
import uuid


def enabled(task):
    return (task or {}).get('review_reuse_policy') == 'incremental-v1'


def finding_facts(entry, record, peers=()):
    from .final_review import latest_verification
    verification = copy.deepcopy(latest_verification(record) or {})
    if isinstance(verification.get('agent'), dict):
        verification['agent'].pop('continuation_source', None)
    return dict(version='incremental-review-v1', claim=entry['frozen_claim'],
        cvss=entry.get('frozen_cvss_assessment'), sources=entry['source_record_refs'],
        verification=verification,
        conflicts=[c for c in entry['conflicts'] if c.get('kind') != 'review_contested'])
    # Peer facts remain inline on every pending item, including accepted peer
    # decisions. Their review/disposition outputs cannot change this claim's
    # input signature. New or changed peers must assess their relation to this
    # unchanged claim rather than making it submit the same verdict again.


def inherit(store, parent_id, child_id, mapping):
    from .continuations import encoded, risk_input
    from .execution_state import stamp
    from .final_review import canonical_groups, comparison_candidates
    from .review_store import fingerprint

    parent_spec=json.loads(store._row('SELECT task_spec FROM runs WHERE id=?',(parent_id,))[0] or '{}')
    if parent_spec.get('capability_policy') != 'audit-capability-v1':
        return dict(findings=0,risks=0)

    owned = {'id','run_id','finding_id','verification_id','item_id','finding_ids','supports',
             'duplicate_of','distinct_from','project_finding_id'}
    def remap(value, field=None):
        # These are original provenance/runner bytes, deliberately retained by
        # continuation cloning. IDs inside them are observations, not ownership.
        if field in {'cvss','job_results','normal_evidence','attack_evidence'}:
            return copy.deepcopy(value)
        if isinstance(value, dict):
            return {k: remap(v,k) for k,v in value.items()}
        if isinstance(value, list):
            return [remap(v,field) for v in value]
        return mapping.get(value,value) if isinstance(value,str) and field in owned else value

    parent_records = store.attach_final_decisions(parent_id, store.list_findings(parent_id))
    child_records = store._review_records(child_id, store.list_findings(child_id))
    old_entries,_ = canonical_groups(parent_records)
    new_entries,_ = canonical_groups(child_records)
    old_raw = {r['id']:r for r in parent_records};new_raw={r['id']:r for r in child_records}
    old_peers = comparison_candidates(old_entries, inclusion_family=store.exhaustive_enabled(parent_id))
    new_peers = comparison_candidates(new_entries, inclusion_family=store.exhaustive_enabled(child_id))
    children={e['canonical_id']:e for e in new_entries}
    candidates={i['item_id']:i for i in store._review_candidates(child_id,'final')}
    carried=[];changed=[]
    for old in old_entries:
        decision = old.get('final_batch_review') or {}
        if old['final_disposition'] != 'accepted' or not decision.get('focus'):
            continue
        key=mapping.get(old['canonical_id'],old['canonical_id']);new=children.get(key)
        if not new:
            continue
        before=remap(finding_facts(old,old_raw[old['frozen_claim']['finding_id']],old_peers.get(old['canonical_id'],[])))
        after=finding_facts(new,new_raw[new['frozen_claim']['finding_id']],new_peers.get(key,[]))
        if encoded(before)==encoded(after) and key in candidates:
            carried.append((candidates[key],remap(decision)))
        else:
            changed.append(dict(item_id=key,changed_facts=[k for k in after if encoded(before.get(k))!=encoded(after[k])]))
    old_risks={i['item_id']:i for i in store._review_candidates(parent_id,'final') if i['kind']=='risk'}
    for row in store._rows("SELECT item_id,revision,decision FROM audit_review_items WHERE run_id=? AND phase='final'",(parent_id,)):
        old=old_risks.get(row['item_id']);new=candidates.get(row['item_id']);decision=json.loads(row['decision'])
        if (not old or not new or row['revision']!=old['revision'] or not decision.get('focus')
                or decision.get('decision') not in {'resolve','skip'}
                or decision.get('risk_outcome') not in {'supported','no_evidence','not_applicable'}):
            continue
        if risk_input(remap(old['payload']),operation_read=old['operation_read'],source_only=True) == risk_input(new['payload'],operation_read=new['operation_read'],source_only=True):
            carried.append((new,remap(decision)))
    if not carried:
        return dict(findings=0,risks=0,changed=changed)
    batch_id=uuid.uuid4().hex;now=stamp();items=[];decisions=[]
    for item,decision in carried:
        decision.update(item_id=item['item_id'],revision=item['revision'],inherited_from_run_id=parent_id)
        items.append(item);decisions.append(decision)
    store._db.execute("INSERT INTO audit_review_batches(id,run_id,epoch,phase,input_hash,items,decisions,status,created_at,finished_at) VALUES(?,?,0,'final',?,?,?,'completed',?,?)",
        (batch_id,child_id,fingerprint(items),encoded(items),encoded(decisions),now,now))
    for item,decision in zip(items,decisions):
        store._db.execute('INSERT OR IGNORE INTO audit_review_items VALUES(?,?,?,?,?,?)',
            (child_id,'final',item['item_id'],item['revision'],batch_id,encoded(decision)))
    result=dict(findings=sum(i['kind']=='finding' for i in items),risks=sum(i['kind']=='risk' for i in items),changed=changed)
    store.append_event(child_id,None,'continuation_reviews_reused',dict(parent_run_id=parent_id,**result))
    return result
