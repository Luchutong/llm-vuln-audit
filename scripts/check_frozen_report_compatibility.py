#!/usr/bin/env python3
"""Check persisted report compatibility on an isolated copy; no model or runner.

The source database is opened read-only. The copy contains original audit data,
so its directory is private and must be kept outside version control.
Run with the backend environment, e.g.:
    uv run --project backend python scripts/check_frozen_report_compatibility.py
"""
import argparse
import asyncio, hashlib, io, json, socket, sqlite3, struct, sys, tempfile, time, zipfile
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--database',type=Path,default=ROOT/'data/audit.db',help='Existing database, opened read-only')
parser.add_argument('--output',type=Path,help='New private directory for the database copy and result.json (default: temporary directory)')
parser.add_argument('--skip-individual-exports',action='store_true',help='Check whole-run artifacts and all source associations without regenerating every individual artifact')
args=parser.parse_args()
if not args.database.is_file():
    parser.error('The source database must already exist')
if args.output:
    OUT=args.output.resolve()
    if OUT==ROOT or ROOT in OUT.parents:
        parser.error('The output must be outside the checkout: it contains private audit data')
    try:
        OUT.mkdir(mode=0o700,parents=True,exist_ok=False)
    except FileExistsError:
        parser.error('The output directory must be new')
else:
    OUT=Path(tempfile.mkdtemp(prefix='vuln-audit-history-check-'))
START=time.monotonic()
def quote(name):
    return '"'+name.replace('"','""')+'"'
def layout(db):
    return {name:[r[1] for r in db.execute('PRAGMA table_info('+quote(name)+')')]
            for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")}
def fingerprint(db, schema):
    result={}
    for name,columns in schema.items():
        if name=='derived_run_reports':
            continue
        h=hashlib.sha256(); count=0
        for row in db.execute('SELECT '+','.join(map(quote,columns))+' FROM '+quote(name)+' ORDER BY rowid'):
            count+=1
            for value in row:
                marker=b'n' if value is None else b'b' if isinstance(value,bytes) else b's' if isinstance(value,str) else b'i' if isinstance(value,int) else b'f'
                content=value if isinstance(value,bytes) else ('' if value is None else str(value)).encode()
                h.update(marker+struct.pack('>Q',len(content))); h.update(content)
        result[name]={'rows':count,'sha256':h.hexdigest()}
    return result
with sqlite3.connect(args.database.resolve().as_uri()+'?mode=ro',uri=True) as original, sqlite3.connect(OUT/'audit.db') as copied:
    original.backup(copied)
with sqlite3.connect(OUT/'audit.db') as copied:
    schema=layout(copied); before=fingerprint(copied,schema)
print(json.dumps({'stage':'snapshot','tables':len(schema),'output':str(OUT)}),flush=True)
# Store initialization is the migration under test. No Services/lifespan/worker is started.
from audit.db import Store
from audit import app as app_module
store=Store(OUT/'audit.db')
class NoSource:
    def __getattr__(self,name):
        raise AssertionError('Historical export attempted live source access: '+name)
app_module.app.state.services=SimpleNamespace(store=store,repository=NoSource())
def deny_connect(*args,**kwargs):
    raise AssertionError('Network access forbidden during historical export checks')
socket.socket.connect=deny_connect
socket.socket.connect_ex=deny_connect
failures=[]; calls=0; individual=0; completed=[]; ledger_checks=0
ledger_sources={}
async def main():
    global calls,individual,ledger_checks
    import httpx
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_module.app),base_url='http://isolated') as api:
        async def request(url):
            global calls
            calls+=1
            response=await api.get(url)
            assert response.status_code==200, f'HTTP {response.status_code}'
            return response
        rows=store._rows('SELECT run_id FROM frozen_run_reports WHERE facts_json IS NOT NULL ORDER BY run_id')
        for row in rows:
            run_id=row['run_id']; frozen=store.frozen_report(run_id)
            try:
                for fmt,key in [('markdown','markdown'),('json','json_export'),('zip','zip_blob')]:
                    original=(frozen[key].encode() if isinstance(frozen[key],str) else frozen[key]) or b''
                    for suffix in ('','&view=archive'):
                        response=await request(f'/api/runs/{run_id}/report?format={fmt}'+suffix)
                        assert response.content==original, 'Archive bytes differ'
                        assert response.headers['etag']=='"'+frozen['output_hash']+'"','Archive ETag differs'
                for view in ('audit','vulnerabilities'):
                    doc=(await request(f'/api/runs/{run_id}/report?view={view}&format=json')).json()
                    assert doc['original_quality_result']==frozen['facts'].get('quality_result'),'Historical fact quality changed'
                    assert doc['run_outcome']==frozen['facts'].get('run_outcome'),'Historical outcome recalculated'
                    assert doc['render_quality']['passed'],str(doc['render_quality']['failed_checks'])
                    md=await request(f'/api/runs/{run_id}/report?view={view}&format=markdown')
                    zipped=await request(f'/api/runs/{run_id}/report?view={view}&format=zip')
                    with zipfile.ZipFile(io.BytesIO(zipped.content)) as z:
                        manifest=json.loads(z.read('manifest.json'))
                        assert z.read(manifest['main_document'])==md.content,'ZIP main document differs'
                        for name,digest in manifest['artifact_hashes'].items():
                            assert hashlib.sha256(z.read(name)).hexdigest()==digest,'Attachment hash mismatch'
                for entry in frozen['facts'].get('canonical_findings') or []:
                    cid=entry['canonical_id']
                    if not args.skip_individual_exports:
                        doc=(await request(f'/api/runs/{run_id}/canonical-findings/{cid}/report?format=json')).json()
                        assert doc['scope']['canonical_ids']==[cid] and doc['counts']['canonical']==1,'Individual scope mismatch'
                        assert doc['render_quality']['passed'],str(doc['render_quality']['failed_checks'])
                        zipped=await request(f'/api/runs/{run_id}/canonical-findings/{cid}/report?format=zip')
                        with zipfile.ZipFile(io.BytesIO(zipped.content)) as z:
                            assert 'final-review.json' not in z.namelist(),'Full parent facts leaked'
                            scoped=json.loads(z.read('finding-facts.json'))
                            assert scoped['scope']['canonical_ids']==[cid],'ZIP individual scope mismatch'
                        individual+=1
                    if store.get_project_finding(cid):
                        if cid not in ledger_sources:
                            ledger_sources[cid]=(await request(f'/api/project-findings/{cid}/reports')).json()
                        sources=ledger_sources[cid]
                        assert any(item['run_id']==run_id and item['canonical_id']==cid for item in sources['items']),'Frozen ledger source missing'
                        ledger_checks+=1
                completed.append(run_id[:8])
            except Exception as e:
                failures.append({'run_alias':run_id[:8],'error':type(e).__name__,'message':str(e)[:180]})
            print(json.dumps({'stage':'run','alias':run_id[:8],'failures':len(failures),'calls':calls}),flush=True)
        for row in store._rows('SELECT run_id FROM frozen_run_reports WHERE facts_json IS NULL ORDER BY run_id'):
            calls+=1
            response=await api.get(f"/api/runs/{row['run_id']}/report?view=audit&format=json")
            if response.status_code!=409 or response.json().get('detail',{}).get('code') not in {'legacy_facts_unavailable','report_not_ready'}:
                failures.append({'run_alias':row['run_id'][:8],'message':'Missing facts must return an explicit 409 without materialization'})
asyncio.run(main())
after=fingerprint(store._db,schema)
changed=[name for name in before if before[name]!=after[name]]
new_schema=layout(store._db)
unmaterialized=[row['run_id'][:8] for row in store._rows('SELECT run_id FROM frozen_run_reports WHERE facts_json IS NULL ORDER BY run_id')]
store.close()
# A second initialization must also preserve old columns and be idempotent.
store=Store(OUT/'audit.db')
assert fingerprint(store._db,schema)==after,'Second initialization changed original rows'
store.close()
result={'source_database_open_mode':'read_only','output_directory':str(OUT),'tables_checked':len(before),'changed_original_tables':changed,
        'new_tables':sorted(set(new_schema)-set(schema)),'new_columns':{name:sorted(set(cols)-set(schema.get(name,[]))) for name,cols in new_schema.items() if name in schema and set(cols)-set(schema[name])},
        'frozen_runs_checked':len(completed),'unmaterialized_frozen_runs':unmaterialized,'individual_exports_skipped':args.skip_individual_exports,'individual_reports_checked':individual,'ledger_source_checks':ledger_checks,'unique_ledger_source_requests':len(ledger_sources),'http_requests':calls,'failures':failures,'seconds':round(time.monotonic()-START,2),
        'no_lifespan_worker_or_model_started':True,'outbound_socket_connections':'forbidden','mutable_source_access':'forbidden'}
(OUT/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(result,ensure_ascii=False,indent=2))
raise SystemExit(1 if failures or changed else 0)
