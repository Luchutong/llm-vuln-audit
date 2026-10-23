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
