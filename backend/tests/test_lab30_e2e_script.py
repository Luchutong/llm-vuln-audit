"""The operator's Lab30 command uses current run/POC contracts without real calls."""
import importlib.util
from pathlib import Path

import httpx
import pytest


PATH = Path(__file__).resolve().parents[2] / 'scripts/run_lab30_e2e.py'
spec = importlib.util.spec_from_file_location('lab30_e2e', PATH)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)


def test_create_freezes_selected_zip_and_automatic_poc_mode():
    requests=[]
    def handle(request):
        import json
        requests.append(json.loads(request.content))
        return httpx.Response(200,json={'id':'run','model':'test'})
    with httpx.Client(base_url='http://test',transport=httpx.MockTransport(handle)) as client:
        result=script.create_run(client,'chosen-zip','sqli',None,3,24,64,'required')
    assert result['id']=='run'
    assert requests[0]['snapshot_id']=='chosen-zip'
    assert requests[0]['poc_mode']=='required'
    assert requests[0]['task']['scenario']=='sqli'
    assert set(requests[0])=={'snapshot_id','task','poc_mode'}


@pytest.mark.parametrize('status',sorted(script.TERMINAL))
def test_real_terminal_status_returns_immediately(status,monkeypatch,capsys):
    def no_sleep(_):raise AssertionError('a completed run must not continue polling')
    monkeypatch.setattr(script.time,'sleep',no_sleep)
    bundle={'run':{'id':'run','status':status},'goal':{},
            'findings':[{'finding_kind':'vulnerability','title':'risk'}]}
    with httpx.Client(base_url='http://test',transport=httpx.MockTransport(lambda req:httpx.Response(200,json=bundle))) as client:
        assert script.poll(client,'run',10,1)==bundle
    assert '漏洞 1' in capsys.readouterr().out


def test_follow_needs_no_zip_and_does_not_create_an_audit(monkeypatch,tmp_path):
    monkeypatch.setattr(script.sys,'argv',['run_lab30_e2e.py','--follow','saved-run','--no-score'])
    class Client:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def get(self,path):return httpx.Response(200,request=httpx.Request('GET','http://test'+path))
    monkeypatch.setattr(script,'client_for',lambda _:Client())
    def forbidden(*args):raise AssertionError('follow must not upload or create')
    monkeypatch.setattr(script,'upload',forbidden)
    monkeypatch.setattr(script,'create_run',forbidden)
    monkeypatch.setattr(script,'poll',lambda client,ident,*args:{'run':{'id':ident,'status':'completed'}})
    assert script.main()==0


def test_scoring_includes_numeric_cvss_and_severity(monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(script.subprocess,'call',lambda command:calls.append(command) or 0)
    assert script.score('run','http://test','sqli',tmp_path/'scores.json')==0
    assert '--check-cvss' in calls[0] and '--check-severity' in calls[0]
    assert calls[0][calls[0].index('--protocol')+1]=='lab30-v2'


def test_closure_create_widens_the_frozen_budget_and_policy():
    requests=[]
    def handle(request):
        import json
        requests.append(json.loads(request.content))
        return httpx.Response(200,json={'id':'run','model':'test'})
    with httpx.Client(base_url='http://test',transport=httpx.MockTransport(handle)) as client:
        script.create_run(client,'zip','all',None,3,24,64,'auto',closure=True)
    payload=requests[0]
    assert payload['budgets']==script.CLOSURE_BUDGETS
    assert payload['run_limits']==script.CLOSURE_LIMITS
    assert payload['task']['completion_policy']=='coverage_review'
    assert payload['task']['baseline_policy']=='fresh'
    assert payload['task']['max_total_attempts']==96


def test_reset_target_reads_the_seed_line_and_refuses_drift(monkeypatch):
    import json, subprocess
    result=subprocess.CompletedProcess([],0,json.dumps({'ok':True,'accounts':[{'username':'alice'}]})+'\n','')
    monkeypatch.setattr(script.subprocess,'run',lambda *a,**k:result)
    assert script.reset_target()=={'ok':True,'accounts':[{'username':'alice'}]}
    drift=subprocess.CompletedProcess([],1,'{"ok":false,"error":"reset_failed"}\n','')
    monkeypatch.setattr(script.subprocess,'run',lambda *a,**k:drift)
    with pytest.raises(SystemExit) as exc:
        script.reset_target()
    assert 'reset_failed' in str(exc.value.code)


def test_closure_metrics_count_events_instead_of_guessing():
    bundle={'run':{'id':'run','status':'completed','poc_policy':{'reset_between_findings':True},
                   'execution_summary':{'stop_reason':{'code':'completed'},
                                        'coverage_review':{'complete':True,'total':3,'pending_total':0,
                                                           'read_paths':['a'],'reviewed_paths':['a','b']},
                                        'context':{'peak_request_bytes':393216,'summary_requests':2,
                                                   'limit_hits':0,'sources':{}},
                                        'run_usage':{'responses':40}}}}
    events=[{'kind':'poc_job_finished'},{'kind':'poc_job_finished'},{'kind':'poc_target_reset'},
            {'kind':'poc_verification_recorded','payload':{'verdict':'confirmed','execution_status':'success'}},
            {'kind':'poc_verification_recorded','payload':{'verdict':'uncertain','execution_status':'authentication_failed'}}]
    config={'agent_policy':{'history_bytes':393216}}
    metrics=script.closure_metrics(bundle,events,config,seed={'ok':True,'accounts':[{},{}]})
    assert metrics['poc']['jobs']==2 and metrics['poc']['confirmed']==1
    assert metrics['poc']['authentication_failed']==1
    assert metrics['coverage']['complete'] is True
    assert metrics['context']['peak_ratio']==1.0 and metrics['context']['summary_requests']==2
    assert metrics['poc']['seed_verified'] is True and metrics['poc']['seed_accounts']==2


def test_closure_problems_names_every_failed_acceptance_condition():
    closure={'status':'failed','coverage':{'complete':False,'pending_total':4},
             'poc':{'jobs':0,'reset_between_findings':False,'seed_verified':False,'authentication_failed':2},
             'context':{'history_limit_hits':1}}
    problems='\n'.join(script.closure_problems(closure,1))
    for expected in ('failed','pending 4','没有 POC 作业','种子','认证失败 2','上下文历史超限 1','退出码 1'):
        assert expected in problems


def test_closure_run_writes_report_and_acceptance_record(monkeypatch,tmp_path):
    score_path=tmp_path/'score_all_v2.json'
    monkeypatch.setattr(script.sys,'argv',['run_lab30_e2e.py','--zip','src.zip','--closure',
                                           '--no-score','--out',str(score_path)])
    class Client:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def get(self,path):
            return httpx.Response(200,request=httpx.Request('GET','http://test'+path))
    monkeypatch.setattr(script,'client_for',lambda _:Client())
    monkeypatch.setattr(script,'closure_config',lambda client:{'agent_policy':{'history_bytes':393216}})
    monkeypatch.setattr(script,'reset_target',lambda *a,**k:{'ok':True,'accounts':[{},{}]})
    monkeypatch.setattr(script,'upload',lambda client,archive:{'id':'snap'})
    monkeypatch.setattr(script,'create_run',lambda *a,**k:{'id':'run-abcdef123456','model':'test'})
    monkeypatch.setattr(script,'poll',lambda *a,**k:{'run':{'id':'run-abcdef123456','status':'completed',
                       'poc_policy':{'reset_between_findings':True},
                       'execution_summary':{'coverage_review':{'complete':True,'pending_total':0},
                                            'context':{'peak_request_bytes':1024,'limit_hits':0}}},'findings':[]})
    monkeypatch.setattr(script,'collect_events',lambda client,run:[{'kind':'poc_job_finished'},
                       {'kind':'poc_verification_recorded','payload':{'verdict':'confirmed','execution_status':'success'}}])
    monkeypatch.setattr(script,'fetch_report',lambda client,run,path:path.write_text('# report') or path)
    assert script.main()==0
    closure=__import__('json').loads((tmp_path/'closure_run-abcd.json').read_text())
    assert closure['status']=='completed' and closure['failed_checks']==[]
    # The run did not really execute POC resets here, so seed verification (not the
    # reset counter) is what this fake proves: acceptance still reads durable fields.
    assert closure['poc']['seed_verified'] is True

