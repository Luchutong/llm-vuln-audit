"""Lab30 routing, authentication, source recognition and removal of the old target."""
import asyncio
import importlib
import io
import json
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from audit import app as app_module
from audit.config import PocSettings
from audit.poc_agent import PocDeps, _http_path_for
from audit.poc_readiness import PocReadinessService
from audit.projects import ensure_project, ensure_projects, project_target_profile
from audit.schemas import CreateRunRequest
from test_project_api import state, _request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
runner = importlib.import_module('poc_runner.runner')
LAB = ROOT / 'labs/lab30'


def archive():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        for path in (LAB / 'app').rglob('*'):
            if path.is_file(): z.writestr(path.relative_to(LAB).as_posix(), path.read_bytes())
    return buffer.getvalue()


@pytest.mark.parametrize('prefix', ['', 'app/', 'lab30-shop/app/'])
def test_fixture_recognition_requires_its_implementation_files(prefix):
    paths = [p.relative_to(LAB / 'app').as_posix() for p in (LAB / 'app').rglob('*') if p.is_file()]
    records = [{'path':prefix + p} for p in paths]
    assert project_target_profile(records) == 'lab30'
    assert project_target_profile([p for p in records if not p['path'].endswith('/template-render.php')]) == 'unknown'
    assert project_target_profile([{'path':'auth/login.php'}, {'path':'index.php'}]) == 'unknown'


def test_old_library_reclassification_preserves_identity_and_activity(state):
    snapshot = state.repository.import_zip(archive(), 'lab30.zip')
    state.store.add_snapshot(snapshot)
    project, _ = ensure_project(state.store, snapshot)
    before = state.store.get_project(project['id'])
    state.store._write("UPDATE snapshots SET target_profile='unknown' WHERE id=?", (snapshot['id'],))
    state.store._write("UPDATE projects SET target_profile='unknown' WHERE id=?", (project['id'],))
    assert ensure_projects(state.store, state.repository) == 0
    after = state.store.get_project(project['id'])
    assert after == {**before, 'target_profile':'lab30'}
    assert state.store.get_snapshot(snapshot['id'])['target_profile'] == 'lab30'
    assert ensure_projects(state.store, state.repository) == 0


def test_service_refreshes_profiles_after_one_time_migration_is_done(tmp_path):
    from audit.config import Settings, ModelConfig
    settings=Settings(data_dir=tmp_path,model=ModelConfig(model='test',base_url='http://127.0.0.1:1/v1',api_key='test'))
    initial=app_module.Services(settings)
    snapshot=initial.repository.import_zip(archive(),'lab30.zip')
    initial.store.add_snapshot(snapshot)
    project,_=ensure_project(initial.store,snapshot)
    before=initial.store.get_project(project['id'])
    initial.store._write("UPDATE snapshots SET target_profile='unknown' WHERE id=?",(snapshot['id'],))
    initial.store._write("UPDATE projects SET target_profile='unknown' WHERE id=?",(project['id'],))
    initial.store.set_schema_meta('project_backfill_v1','done')
    initial.store.close()
    restarted=app_module.Services(settings)
    try:
        assert restarted.store.schema_meta('project_backfill_v1')=='done'
        assert restarted.store.get_snapshot(snapshot['id'])['target_profile']=='lab30'
        assert restarted.store.get_project(project['id'])=={**before,'target_profile':'lab30'}
        assert restarted.store.get_project(project['id'])['snapshot_count']==1
    finally:restarted.store.close()


def test_required_run_freezes_lab30_target_without_contacting_models(state):
    snapshot = state.repository.import_zip(archive(), 'lab30.zip')
    state.store.add_snapshot(snapshot)
    ensure_project(state.store, snapshot)
    state.settings.poc = PocSettings(runner_url='http://test-runner')
    class Client:
        async def health(self): return {'ok':True, 'supported_targets':['lab30'], 'capabilities':{name: True for name in ('verification_contexts', 'identity_preconditions', 'idempotent_jobs', 'idempotent_http_jobs', 'idempotent_browser_jobs')}}
        async def aclose(self): pass
    state.poc_readiness = PocReadinessService(state.settings, client_factory=Client)
    result = asyncio.run(app_module.create_run(_request(state), CreateRunRequest(
        snapshot_id=snapshot['id'], poc_mode='required', task={'objective':'审计商城入口的输入传播、权限边界及危险操作'})))
    assert result['poc_policy']['target'] == 'lab30'
    assert result['target_profile'] == 'lab30'
    assert state.store.execution_summary(result['id'])['poc']['available']


def test_removed_target_never_reaches_runner_or_passes_readiness(tmp_path,monkeypatch):
    monkeypatch.setattr(runner, 'TOKEN', 'test-only-token')
    monkeypatch.setattr(runner, 'WORKDIR', tmp_path)
    client = TestClient(runner.app)
    headers = {'Authorization':'Bearer test-only-token'}
    for endpoint, body in [('/v1/targets/dvwa/prepare',{}),('/v1/http',{'target':'dvwa','path':'/login.php'}),
                           ('/v1/jobs',{'target':'dvwa','language':'python','script':'pass'}),
                           ('/v1/browser/check',{'target':'dvwa','path':'/'})]:
        assert client.post(endpoint,json=body,headers=headers).status_code == 404
    def forbidden(): raise AssertionError('removed targets must not contact a runner')
    settings = SimpleNamespace(poc=PocSettings(runner_url='http://test-runner'))
    service = PocReadinessService(settings,client_factory=forbidden)
    assert asyncio.run(service.check('dvwa'))['reason'] == 'unsupported_target'
    assert asyncio.run(service.check('lab30', target='dvwa'))['reason'] == 'unsupported_target'
    assert runner.healthz()['supported_targets'] == ['lab30']


def test_stale_environment_target_cannot_switch_new_configuration():
    assert PocSettings.from_environ({'POC_TARGET':'dvwa'}).target == 'lab30'


def test_old_runner_requires_rebuild_before_lab30_is_ready():
    class Client:
        async def health(self):return {'ok':True,'target':'dvwa'}
        async def aclose(self):pass
    service=PocReadinessService(SimpleNamespace(poc=PocSettings(runner_url='http://runner')),client_factory=Client)
    result=asyncio.run(service.check('lab30'))
    assert not result['available'] and '重建' in result['message']


@pytest.mark.parametrize('login_status,member_status,success', [(302,200,True),(401,401,False),(302,401,False)])
def test_prepare_authenticates_member_and_reuses_session(tmp_path,monkeypatch,login_status,member_status,success):
    seen=[]
    def handle(request):
        seen.append(request)
        if request.url.path == '/health.php': return httpx.Response(200,json={'ok':True,'version':'1.0.0'})
        if request.method == 'POST':
            assert request.url.path == '/auth/login.php'
            assert request.content == b'username=alice&password=Alice123%21'
            return httpx.Response(login_status,headers={'Location':'/','Set-Cookie':'SHOPSESSID=member-session; Path=/'})
        if request.url.path == '/auth/login.php': return httpx.Response(200,text='login')
        assert 'SHOPSESSID=member-session' in request.headers.get('cookie','')
        if request.url.path == '/account/me.php':
            return httpx.Response(member_status,json={'id':1,'username':'alice','role':'customer'})
        return httpx.Response(member_status,text='member')
    # A 401 on the cached session makes the runner re-login with a fresh client, so the
    # factory has to hand out a new one instead of the instance it just closed.
    def make_client():
        return httpx.Client(base_url=runner.LAB30_URL,transport=httpx.MockTransport(handle),follow_redirects=False)
    client=make_client()
    monkeypatch.setattr(runner,'_lab30_client',make_client)
    monkeypatch.setattr(runner,'WORKDIR',tmp_path)
    monkeypatch.setattr(runner,'_contexts',{})
    monkeypatch.setattr(runner,'_leases',{})
    # There is no process-wide account baseline any more: drift inside one context is
    # reported as state_drift, and only the role is a hard precondition.
    monkeypatch.setattr(runner,'LAB30_USER','alice');monkeypatch.setattr(runner,'LAB30_PASSWORD','Alice123!')
    try:
        context=runner.create_context(runner.ContextRequest(run_id='test-run',finding_id='test-finding'))['context_id']
        if not success:
            assert not runner._prepare_sync(context_id=context)['ok']
        else:
            result=runner._prepare_sync(context_id=context)
            assert result['ok'] and result['user']=='alice'
            observed=runner._observe_sync(runner.HttpRequest(path='/orders/index.php',context_id=context))
            assert observed['status']==200
            assert runner._prepared_cookies(context)==[{'name':'SHOPSESSID','value':'member-session','url':runner.LAB30_URL+'/'}]
            assert asyncio.run(runner.target_status('lab30',context_id=context))['authenticated']
            assert not any(request.url.path in {'/setup.php','/security.php'} for request in seen)
    finally:client.close()


def test_script_process_receives_only_lab30_fixture_environment(tmp_path,monkeypatch):
    monkeypatch.setattr(runner,'WORKDIR',tmp_path)
    monkeypatch.setattr(runner,'_jobs',{})
    result=runner._execute(runner.JobRequest(language='python',script='''import os
assert os.environ['LAB30_URL']
assert os.environ['LAB30_USER']
assert os.environ['LAB30_PASSWORD']
assert not any(key.startswith('DVWA_') for key in os.environ)
print('lab30-environment-ok')
'''))
    assert result['exit_code']==0,result['stderr']
    assert result['stdout'].strip()=='lab30-environment-ok'


@pytest.mark.parametrize('source,route', [('app/public/auth/login.php','/auth/login.php'),
    ('lab30-shop/app/public/orders/detail.php','/orders/detail.php'),('public/catalog/index.php','/catalog/index.php'),
    ('app/src/bootstrap.php','/'),('app/public/../src/bootstrap.php','/')])
def test_source_routes_follow_actual_document_root(source,route):
    assert _http_path_for(source)==route


@pytest.mark.parametrize('path', ['/', '/health.php','/catalog/detail.php?id=1','/auth/continue.php?next=//example.test',
    '/orders/index.php','/wallet/withdraw.php','/account/me.php','/ops/index.php','/partner/token.php',
    '/support/messages.php','/content/page.php'])
def test_all_business_routes_are_available_to_observation(path):
    assert runner._check_path(path)==path
