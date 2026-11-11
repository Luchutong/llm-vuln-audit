"""Recover a lost POC interpretation from immutable, completed runner facts."""
import copy
import json
import uuid
from types import SimpleNamespace


def publish(store, run_id, finding_id, verification_id, result, *, actor):
    from .execution_state import stamp
    from .poc_agent import evidence_errors
    from .schemas import PocVerificationResult
    value=PocVerificationResult.model_validate(result)
    if not actor or value.status not in {'verified','rejected'}:
        raise ValueError('须明确记录审查者及有真实对照的确定结论')
    with store._lock:
        store._db.execute('BEGIN IMMEDIATE')
        try:
            state=store._row('SELECT r.status,e.phase FROM runs r JOIN run_execution_state e ON e.run_id=r.id WHERE r.id=?',(run_id,))
            if not state or state['status']!='paused' or state['phase']!='paused' or run_id in store._active_clocks:
                raise ValueError('原始作业结论恢复要求静止暂停检查点')
            finding=store.get_finding(finding_id)
            if not finding or finding['run_id']!=run_id:raise ValueError('发现不属于本记录')
            old=next((v for v in finding.get('verifications') or [] if v['id']==verification_id),None)
            if not old or old['status']!='inconclusive':raise ValueError('仅可恢复已存作业但结论未发布的验证')
            attempt=store._row('SELECT * FROM poc_attempts WHERE run_id=? AND finding_id=? AND verification_id=?',(run_id,finding_id,verification_id))
            if (not attempt or attempt['state']!='completed' or attempt['finding_revision']!=int(finding.get('revision') or 1)
                    or attempt['revision']!=int(finding.get('project_revision') or finding.get('revision') or 1)):
                raise ValueError('原验证并非当前版本的完成尝试')
            agent=old.get('agent') or {};context=agent.get('context_id')
            closed=store._row("SELECT payload FROM events WHERE run_id=? AND kind='poc_context_closed' AND json_extract(payload,'$.context_id')=? ORDER BY id DESC LIMIT 1",(run_id,context))
            closure=json.loads(closed[0]) if closed else {}
            if closure.get('state')!='closed' or closure.get('active')!=0 or closure.get('pending_jobs')!=0:
                raise ValueError('原上下文尚未关闭')
            errors=evidence_errors(value,SimpleNamespace(finding=finding,jobs=agent.get('job_results') or [],context_id=context))
            if errors:raise ValueError('；'.join(errors))
            record=copy.deepcopy(old)
            record.update(id=uuid.uuid4().hex,created_at=stamp(),status=value.status,verdict=value.verdict,
                          execution_status='success',source='operator',normal_observation=value.normal_observation,
                          attack_observation=value.attack_observation,notes=value.evidence_notes,
                          modification_notes='人工核读已完成的原实验并补齐结论，未重放作业。',browser_execution=value.browser_execution)
            record['agent'].update(assessment_source='operator',assessment_actor=actor,recovered_from=old['id'],
                reason='operator_review_completed',summary=value.summary,jobs=value.jobs,
                normal_evidence=[r.model_dump() for r in value.normal_evidence],
                attack_evidence=[r.model_dump() for r in value.attack_evidence],experiment=value.experiment.model_dump() if value.experiment else None)
            store._insert_verification(record)
            store._db.execute('UPDATE findings SET verification_status=?,verification_verdict=? WHERE id=?',(value.status,value.verdict,finding_id))
            if finding.get('project_finding_id'):
                store._db.execute('UPDATE project_findings SET verification_status=?,verification_verdict=?,latest_verification_id=? WHERE id=? AND revision=?',
                    (value.status,value.verdict,record['id'],finding['project_finding_id'],attempt['revision']))
            store._db.execute('UPDATE poc_attempts SET verification_id=?,updated_at=? WHERE key=?',(record['id'],stamp(),attempt['key']))
            store.append_event(run_id,None,'operator_verification_recovered',dict(actor=actor,finding_id=finding_id,
                previous_verification_id=old['id'],verification_id=record['id'],job_ids=value.jobs,status=value.status,model_requests=0,new_experiments=0))
            store._db.execute('COMMIT');return record
        except BaseException:
            if store._db.in_transaction:store._db.execute('ROLLBACK')
            raise
