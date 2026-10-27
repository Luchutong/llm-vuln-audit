"""Host CVSS calculation, provenance, project revisions and migration."""
import threading

import pytest
from audit.cvss31 import BASE
from audit.cvss_assessment import propose
from audit.cvss_store import CvssConflict
from audit.evidence import validate_evidence
from audit.db import Store
from test_project_findings_api import state, project, run, finding, verification


def metrics(manual=False, values='NLNNUHNN'):
    return {key:{'value':value,'rationale':f'{key} has a source-backed condition',
        'evidence':[] if manual else [{'path':'a.php','start_line':2,'end_line':3}],
        'assumption':manual} for key,value in zip(BASE,values)}


def body(row):
    return dict(metrics=metrics(True),reason='明确各项攻击条件与影响',expected_revision=row['revision'],
        expected_assessment_revision=row['cvss_assessment']['assessment_revision'])


def test_auto_requires_actual_read_ledger_not_model_score():
    m=metrics();m.update(base_score=10,severity='critical')
    validate=lambda refs:validate_evidence(refs,{'a.php':20},[('a.php',1,5)])
    result=propose(m,validate_refs=validate,snapshot_id='actual-zip',run_id='run')
    assert result['cvss']['base_score']==7.5 and result['severity']=='high'
    assert result['cvss_assessment']['metric_details']['PR']['evidence'][0]['snapshot_id']=='actual-zip'
    bad=propose(m,validate_refs=lambda refs:validate_evidence(refs,{'a.php':20},[('a.php',8,10)]))
    assert bad['cvss'] is None and bad['severity']=='unknown'


@pytest.mark.parametrize('value',[None,{}, {'AV':'N'}, {'AV':{'value':'N','rationale':'','evidence':[]}}, {'AV':{'value':'X'}}])
def test_partial_proposals_remain_recordable(value):
    result=propose(value)
    assert result['cvss'] is None
    assert len(result['cvss_assessment']['metric_details'])==8
    assert result['cvss_assessment']['issues']


def test_preview_save_conflict_zero_and_unchanged_verification(state):
    p=project(state.store);r,_=run(state.store,p);ledger,fid=finding(state.store,p,r)
    verification(state.store,fid,ledger)
    original=state.store.get_finding(fid)
    row=state.store.get_project_finding(ledger)
    assert row['cvss'] is None and row['legacy_severity']=='high'
    path=f'/api/project-findings/{ledger}/cvss';payload=body(row)
    preview=state.client.post(path+'/preview',json=payload)
    assert preview.status_code==200,preview.text
    assert preview.json()['cvss']['base_score']==7.5
    assert state.store.get_project_finding(ledger)['cvss'] is None
    saved=state.client.put(path,json=payload)
    assert saved.status_code==200,saved.text
    row=saved.json()
    assert row['cvss']['base_score']==7.5 and row['revision']==1
    assert row['verification_status']=='verified' and state.store.get_finding(fid)==original
    assert state.client.put(path,json=payload).status_code==409
    assert state.client.post(path+'/preview',json=payload).status_code==409
    zero=body(row);zero['metrics']=metrics(True,'NLNRUNNN')
    saved=state.client.put(path,json=zero)
    assert saved.status_code==200,saved.text
    assert saved.json()['cvss']['base_score']==0 and saved.json()['severity']=='none'
    assert saved.json()['verification_status']=='verified'
    assert state.client.get('/api/project-findings?severity=none&cvss_status=scored').json()['total']==1
    history=state.client.get(f'/api/project-findings/{ledger}/cvss-history?limit=1').json()
    assert history['total']==3 and len(history['items'])==1
    assert history['items'][0]['cvss_assessment']['reason']==payload['reason']


def test_manual_validation(state):
    p=project(state.store);r,_=run(state.store,p);ledger,_=finding(state.store,p,r)
    row=state.store.get_project_finding(ledger);path=f'/api/project-findings/{ledger}/cvss'
    for change in ('missing','invalid','unsupported','no_basis'):
        payload=body(row)
        if change=='missing': del payload['metrics']['AC']
        if change=='invalid': payload['metrics']['PR']['value']='X'
        if change=='unsupported': payload['metrics']['base_score']=10
        if change=='no_basis': payload['metrics']['AV']['assumption']=False
        response=state.client.put(path,json=payload)
        assert response.status_code==422,(change,response.text)
    assert state.client.post('/api/project-findings/missing/cvss/preview',json=body(row)).status_code==404
    assert state.client.get(f'/api/project-findings/{ledger}/cvss-history?offset=-1').status_code==422


def test_manual_precedence_and_conclusion_change(state):
    p=project(state.store);r,_=run(state.store,p);ledger,fid=finding(state.store,p,r)
    verification(state.store,fid,ledger)
    response=state.client.put(f'/api/project-findings/{ledger}/cvss',json=body(state.store.get_project_finding(ledger)))
    assert response.status_code==200,response.text
    r2,_=run(state.store,p,'repacked.zip');finding(state.store,p,r2)
    row=state.store.get_project_finding(ledger)
    assert row['cvss_assessment']['source']=='manual' and row['cvss']['base_score']==7.5
    assert row['verification_status']=='verified' and row['revision']==1
    r3,_=run(state.store,p,'new-conclusion.zip');finding(state.store,p,r3,corrected=True)
    row=state.store.get_project_finding(ledger)
    assert row['revision']==2 and row['cvss'] is None and row['verification_status']=='stale'
    items=state.store.project_cvss_history(ledger)['items']
    assert any(not item['applicable'] and item['cvss_assessment']['source']=='manual' and item['cvss_assessment']['status']=='stale' for item in items)


def test_source_deletion_preserves_rating_history(state):
    p=project(state.store);r,_=run(state.store,p);ledger,_=finding(state.store,p,r)
    state.client.put(f'/api/project-findings/{ledger}/cvss',json=body(state.store.get_project_finding(ledger)))
    state.store._write("UPDATE runs SET status='completed' WHERE id=?",(r,));state.store.delete_run(r)
    history=state.store.project_cvss_history(ledger)
    assert history['total']==2 and not history['items'][0]['source_run_available']
    assert state.store.get_project_finding(ledger)['cvss']['base_score']==7.5


def test_legacy_migration_is_idempotent(tmp_path):
    path=tmp_path/'audit.db';store=Store(path)
    p=project(store);r,_=run(store,p);ledger,fid=finding(store,p,r);verification(store,fid,ledger)
    for table,ident in [('findings',fid),('project_findings',ledger)]:
        store._write(f"UPDATE {table} SET severity='critical',cvss_assessment=NULL,legacy_severity=NULL WHERE id=?",(ident,))
    store.close()
    for _ in range(2):
        store=Store(path)
        for row in [store.get_finding(fid),store.get_project_finding(ledger)]:
            assert row['severity']=='unknown' and row['legacy_severity']=='critical'
            assert row['cvss'] is None and row['cvss_assessment']['status']=='legacy_unrated'
        assert store.get_project_finding(ledger)['verification_status']=='verified'
        store.close()


def test_worker_pipeline_scores_using_exact_reads_and_persists(state,tmp_path):
    from audit.source import SourceRepository
    from audit.worker import _normalise_task_findings
    from test_goal_tasks import create_planner_run,make_worker,worker_outcome,proposal
    repository=SourceRepository(tmp_path/'sources')
    current,_=create_planner_run(state.store,repository)
    p=project(state.store)
    state.store._write('UPDATE runs SET project_id=? WHERE id=?',(p,current['id']))
    worker=make_worker(state.store,repository)
    m=metrics()
    for item in m.values(): item['evidence']=[{'path':'public/index.php','start_line':1,'end_line':4}]
    payload={'title':'原始源码支持的注入风险','kind':'vulnerability','summary':'外部请求输入直接进入危险操作，缺少参数约束。',
             'severity':'critical','evidence':'public/index.php:4-4','cvss_input':m,
             'vulnerability_type':'sqli','primary_location':{'path':'public/index.php','line':4}}
    outcome=worker_outcome('achieved',finding=payload,seen=[{'path':'public/index.php','start_line':1,'end_line':4}])
    result=worker._build_planner_findings(current,{'id':'task',**proposal('entry-flow')},_normalise_task_findings(outcome))[0]
    assert result['candidate'] and result['record']['cvss']['base_score']==7.5
    worker._record_finding(current['id'],'task',result)
    row=state.store.list_findings(current['id'])[0]
    assert row['severity']=='high' and row['cvss']['base_score']==7.5
    assert state.store.list_planner_findings(current['id'])[0]['cvss']['base_score']==7.5
    # A pure rating correction reuses the finding ID and keeps that canonical source.
    m['C']['value']='N'
    revised=worker._build_planner_findings(current,{'id':'task',**proposal('entry-flow')},_normalise_task_findings(outcome))[0]
    worker._record_finding(current['id'],'task',revised)
    latest=state.store.get_project_finding(row['project_finding_id'])
    assert latest['last_finding_id']==row['id']
    assert latest['cvss']['base_score']==0 and latest['revision']==1


def test_rating_only_update_does_not_change_run_revision_or_early_verification(state):
    p=project(state.store);r,_=run(state.store,p);ledger,fid=finding(state.store,p,r)
    verification(state.store,fid,ledger)
    record=state.store.get_finding(fid)
    old_revision=record['revision']
    record.update(propose(metrics(True),source='manual'))
    state.store.add_finding(record)
    row=state.store.get_finding(fid)
    assert row['revision']==old_revision and row['cvss']['base_score']==7.5
    assert row['verifications'] and row['verification_status']=='verified'
    assert row['superseded_summary']==[]


def test_pre_cvss_database_is_backed_up_before_additive_migration(tmp_path):
    import sqlite3
    path=tmp_path/'legacy.db';store=Store(path)
    p=project(store);r,_=run(store,p);ledger,fid=finding(store,p,r)
    for table in ('findings','project_findings'):
        store._write(f"UPDATE {table} SET severity='high'")
        for key in ('cvss','cvss_assessment','legacy_severity'):
            store._write(f'ALTER TABLE {table} DROP COLUMN {key}')
    store.close()
    store=Store(path)
    backups=list(tmp_path.glob('legacy.db.pre-cvss31-*.bak'))
    assert len(backups)==1
    assert backups[0].stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(backups[0]) as original:
        assert original.execute('SELECT severity FROM findings WHERE id=?',(fid,)).fetchone()[0]=='high'
        assert 'cvss' not in {row[1] for row in original.execute('PRAGMA table_info(findings)')}
    assert store.get_finding(fid)['severity']=='unknown'
    store.close()
    store=Store(path);store.close()
    assert len(list(tmp_path.glob('legacy.db.pre-cvss31-*.bak')))==1


def test_concurrent_manual_saves_serialise_and_lose_explicitly(state):
    p=project(state.store);r,_=run(state.store,p);ledger,_=finding(state.store,p,r)
    row=state.store.get_project_finding(ledger)
    versions={'expected_revision':row['revision'],
              'expected_assessment_revision':row['cvss_assessment']['assessment_revision']}
    barrier=threading.Barrier(2);outcomes=[]
    def save():
        rating=propose(metrics(True),source='manual')
        barrier.wait()
        try:
            state.store.update_project_cvss(ledger,rating,reason='并发修订同一结论',**versions)
            outcomes.append('saved')
        except CvssConflict:
            outcomes.append('conflict')
    threads=[threading.Thread(target=save) for _ in range(2)]
    for thread in threads: thread.start()
    for thread in threads: thread.join(timeout=10)
    assert sorted(outcomes)==['conflict','saved']
    current=state.store.get_project_finding(ledger)
    assert current['cvss']['base_score']==7.5
    assert current['cvss_assessment']['assessment_revision']==2
    assert state.store.project_cvss_history(ledger)['total']==2


def test_unchanged_conclusion_keeps_ledger_rating_and_new_run_keeps_its_own(state):
    from audit.project_findings import ledger_record
    p=project(state.store);r,snapshot=run(state.store,p);ledger,fid=finding(state.store,p,r)
    record=state.store.get_finding(fid)
    record.update(propose(metrics(),snapshot_id=snapshot,run_id=r))
    state.store.add_finding(record)
    state.store.merge_project_finding(p,r,ledger_record(record))
    assert state.store.get_project_finding(ledger)['cvss']['base_score']==7.5
    # A second run re-discovers the same conclusion but rates it differently.  The
    # ledger's rating stays with its conclusion version; the new run keeps its own.
    r2,snapshot2=run(state.store,p,'repacked.zip');same,new_fid=finding(state.store,p,r2)
    assert same==ledger
    changed=metrics();changed['C']['value']='N'
    record2=state.store.get_finding(new_fid)
    record2.update(propose(changed,snapshot_id=snapshot2,run_id=r2))
    state.store.add_finding(record2)
    state.store.merge_project_finding(p,r2,ledger_record(record2))
    current=state.store.get_project_finding(ledger)
    assert current['revision']==1 and current['cvss']['base_score']==7.5
    assert current['cvss_assessment']['run_id']==r
    fresh=state.store.get_finding(new_fid)
    assert fresh['cvss']['base_score']==0 and fresh['severity']=='none'
    # Only the first automatic rating and the initial legacy record: the later
    # rediscovery added a run relation, not a ledger rating revision.
    assert state.store.project_cvss_history(ledger)['total']==2


def test_conclusion_change_replaces_the_rating_and_marks_it_not_applicable(state):
    from audit.project_findings import ledger_record
    p=project(state.store);r,snapshot=run(state.store,p);ledger,fid=finding(state.store,p,r)
    record=state.store.get_finding(fid)
    record.update(propose(metrics(),snapshot_id=snapshot,run_id=r))
    state.store.add_finding(record)
    state.store.merge_project_finding(p,r,ledger_record(record))
    r2,_=run(state.store,p,'corrected.zip');finding(state.store,p,r2,corrected=True)
    current=state.store.get_project_finding(ledger)
    assert current['revision']==2 and current['cvss'] is None
    assert current['cvss_assessment']['status'] in ('needs_information','legacy_unrated')
    history=state.store.project_cvss_history(ledger)['items']
    applicable=[item for item in history if item['applicable']]
    superseded=[item for item in history if not item['applicable'] and item['cvss']]
    assert len(applicable)==1 and superseded
    assert superseded[0]['cvss']['base_score']==7.5
    assert superseded[0]['cvss_assessment']['status']=='stale'


def test_manual_source_refs_use_actual_snapshot_and_reject_invented_lines(state,tmp_path):
    from audit.source import SourceRepository
    from test_goal_tasks import create_planner_run
    repository=SourceRepository(tmp_path/'sources')
    current,_=create_planner_run(state.store,repository)
    # Build a canonical finding with source ranges in this actual snapshot.
    from audit.project_findings import ledger_record
    from test_project_findings import _finding
    record=_finding(path='public/index.php',evidence=[{'path':'public/index.php','start_line':1,'end_line':4}])
    state.store.add_project({'id':'cvss-project','name':'Test','content_key':'cvss-content'})
    record['run_id']=current['id']
    result=state.store.merge_project_finding('cvss-project',current['id'],ledger_record(record))
    ledger=result['project_finding_id'];state.repository=repository
    payload=body(state.store.get_project_finding(ledger))
    for item in payload['metrics'].values():
        item.update(assumption=False,evidence=[{'path':'public/index.php','start_line':1,'end_line':4}])
    response=state.client.post(f'/api/project-findings/{ledger}/cvss/preview',json=payload)
    assert response.status_code==200,response.text
    assert response.json()['cvss_assessment']['snapshot_id']==current['snapshot_id']
    payload['metrics']['AV']['evidence'][0]['end_line']=999999
    assert state.client.put(f'/api/project-findings/{ledger}/cvss',json=payload).status_code==422


def test_fixed_category_worker_also_uses_the_shared_host_scoring(state,tmp_path):
    from audit.source import SourceRepository
    from audit.schemas import Check,EvidenceRef
    from test_goal_tasks import create_planner_run,make_worker
    repository=SourceRepository(tmp_path/'sources')
    current,_=create_planner_run(state.store,repository)
    p=project(state.store)
    state.store._write('UPDATE runs SET project_id=? WHERE id=?',(p,current['id']))
    m=metrics()
    for item in m.values():item['evidence']=[{'path':'public/index.php','start_line':1,'end_line':4}]
    from audit.schemas import PocSpec
    proof=PocSpec(filename='proof.py',language='python',script="print('proof')",instructions='针对本地授权靶场运行',normal_input='normal',attack_input='attack',expected_result='可观测差异')
    check=Check(conclusion='candidate',reasoning='请求参数拼接进入查询结构',evidence=[EvidenceRef(path='public/index.php',start_line=1,end_line=4)],
        input_source='请求参数',propagation='直接拼接',dangerous_operation='query',preconditions=['允许访问入口'],poc=proof,remediation='使用参数绑定',cvss_input=m)
    worker=make_worker(state.store,repository)
    worker._store_findings(current,{'unit_id':'fixed','file_path':'public/index.php','symbol':'<top>','start_line':1,'end_line':4},
        {'checks':{'sqli':check},'seen':[{'path':'public/index.php','start_line':1,'end_line':4}],'seen_exact':True})
    result=state.store.list_findings(current['id'])[0]
    assert result['cvss']['base_score']==7.5 and result['severity']=='high'
    check.cvss_input['PR']['value']='H'
    worker._store_findings(current,{'unit_id':'fixed','file_path':'public/index.php','symbol':'<top>','start_line':1,'end_line':4},
        {'checks':{'sqli':check},'seen':[{'path':'public/index.php','start_line':1,'end_line':4}],'seen_exact':True})
    latest=state.store.get_project_finding(result['project_finding_id'])
    assert latest['last_finding_id']==result['id']
    assert latest['cvss']['base_score']==4.9 and latest['revision']==1


def test_incomplete_rediscovery_keeps_applicable_auto_rating(state):
    from audit.project_findings import ledger_record
    p=project(state.store);r,snapshot=run(state.store,p);ledger,fid=finding(state.store,p,r)
    record=state.store.get_finding(fid)
    record.update(propose(metrics(),snapshot_id=snapshot,run_id=r))
    state.store.add_finding(record)
    state.store.merge_project_finding(p,r,ledger_record(record))
    before=state.store.get_project_finding(ledger)
    r2,_=run(state.store,p,'repacked.zip');same,new_fid=finding(state.store,p,r2)
    after=state.store.get_project_finding(ledger)
    assert same==ledger and after['revision']==before['revision']
    assert after['cvss']==before['cvss'] and after['cvss_assessment']==before['cvss_assessment']
    assert after['cvss_assessment']['run_id']==r
    assert state.store.get_finding(new_fid)['cvss'] is None
    r3,_=run(state.store,p);finding(state.store,p,r3,corrected=True)
    assert state.store.get_project_finding(ledger)['cvss'] is None


def test_markdown_exports_metric_evidence_gaps_and_rating_provenance():
    from audit.cvss_assessment import rating_details_lines
    from audit.report import _task_finding_block
    from audit.report_facts import render_host_summary
    record={'id':'run-finding','revision':3,'finding_kind':'vulnerability','category':'task_goal',
            'title':'证据支持的风险','summary':'独立风险结论','validation_state':'candidate',
            **propose(metrics(),snapshot_id='actual-zip',run_id='original-run')}
    markdown='\n'.join(_task_finding_block(record,1))
    host=render_host_summary({'run_id':'original-run','status':'completed','complete':True,
        'raw_finding_count':1,'valid_finding_count':1,'ledger_group_count':1,'tasks':[],
        'finding_groups':[{'id':'ledger','findings':[record]}]})
    for text in (markdown,host):
        assert 'Base 7.5 (high)' in text
        assert 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' in text
        assert '来源任务：original-run' in text and '来源 ZIP 快照：actual-zip' in text
        for metric in BASE:
            assert f'| {metric} |' in text and f'{metric} has a source-backed condition' in text
        assert 'a.php:2-3 (ZIP actual-zip)' in text
    partial=propose({'AV':{'value':None,'rationale':'尚未确认入口','evidence':[]}})
    text='\n'.join(rating_details_lines(partial))
    assert '待补充指标' in text and '尚未确认入口' in text and '指标待补充' in text
    assert '0.0' not in text
    manual=propose(metrics(True),source='manual')
    manual['cvss_assessment']['reason']='核对部署前提 | 明确人工假设'
    text='\n'.join(rating_details_lines(manual))
    assert '人工假设' in text and '修订原因：核对部署前提 &#124;' in text


def test_cvss_migration_failure_rolls_back_schema_and_data(tmp_path,monkeypatch):
    import sqlite3
    path=tmp_path/'legacy.db';store=Store(path)
    p=project(store);r,_=run(store,p);_,fid=finding(store,p,r)
    for table in ('findings','project_findings'):
        store._write(f"UPDATE {table} SET severity='high'")
        for key in ('cvss','cvss_assessment','legacy_severity'):
            store._write(f'ALTER TABLE {table} DROP COLUMN {key}')
    store.close()
    def fail(*args,**kwargs):raise RuntimeError('simulated migration failure')
    with monkeypatch.context() as patch:
        patch.setattr(Store,'_write_cvss',fail)
        failed=Store.__new__(Store)
        with pytest.raises(RuntimeError,match='simulated migration failure'):failed.__init__(path)
        failed.close()
    with sqlite3.connect(path) as db:
        assert 'cvss' not in {row[1] for row in db.execute('PRAGMA table_info(findings)')}
        assert db.execute('SELECT severity FROM findings WHERE id=?',(fid,)).fetchone()[0]=='high'
    store=Store(path)
    assert store.get_finding(fid)['legacy_severity']=='high'
    store.close()


def test_manual_rating_leaves_frozen_host_facts_unchanged(state):
    p=project(state.store);r,_=run(state.store,p);ledger,_=finding(state.store,p,r)
    state.store.terminate_execution(r,'completed',{'code':'goal_met','message':'已保存证据'})
    frozen=state.store.get_final_summary(r)
    assert frozen['finding_groups'][0]['findings'][0]['cvss'] is None
    response=state.client.put(f'/api/project-findings/{ledger}/cvss',json=body(state.store.get_project_finding(ledger)))
    assert response.status_code==200,response.text
    assert response.json()['cvss']['base_score']==7.5
    assert state.store.get_final_summary(r)==frozen
