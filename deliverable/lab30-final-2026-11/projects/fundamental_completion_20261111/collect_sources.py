"""Export only required read-only evidence, retaining raw fingerprints and redaction counts."""
import collections, datetime as dt, hashlib, importlib.util, json, re, sqlite3, subprocess
from pathlib import Path

HERE=Path(__file__).resolve().parent
REPO=Path('/home/luchitong/work/vuln-audit')
spec=importlib.util.spec_from_file_location('collector_reference',HERE.parent/'closure_evidence_20261111/collect_evidence.py')
# Do not import the historical collector: its module body performs a collection.
COUNTS=collections.Counter()
def sha(b): return hashlib.sha256(b).hexdigest()
def clean(v,key=''):
    if re.fullmatch(r'(?:authorization|proxy.authorization|cookie|set.cookie|password|passwd|api.key|access.token|refresh.token|auth.token|capability.token|session.id|secret|encrypted.*)',key,re.I) and v:
        COUNTS[key]+=1; return '[REDACTED]'
    if isinstance(v,dict): return {k:clean(x,k) for k,x in v.items()}
    if isinstance(v,list): return [clean(x) for x in v]
    if isinstance(v,str):
        for pattern,repl in [(r'\bsk-[A-Za-z0-9_-]{16,}','[REDACTED_API_KEY]'),(r'(?im)^(\s*(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie)\s*:\s*)[^\n]+',r'\1[REDACTED]'),(r'(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]{12,}',r'\1[REDACTED]'),(r'(?i)(\b(?:PHPSESSID|sessionid|csrf_token)=)[^\s;"&<>]+',r'\1[REDACTED]')]:
            v,n=re.subn(pattern,repl,v); COUNTS[pattern]+=n
    return v
def save(p,v):
    p=HERE/p; p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def unpack(row):
    d=dict(row)
    for k,v in list(d.items()):
        if isinstance(v,str) and v[:1] in ('{','['):
            try:d[k]=json.loads(v)
            except ValueError:pass
    return d

started=dt.datetime.now(dt.timezone.utc).isoformat()
db=sqlite3.connect(f'file:{REPO/"data/audit.db"}?mode=ro',uri=True); db.row_factory=sqlite3.Row
db.execute('BEGIN')
RUNS={'old':'2969bcf204cd43b5baf2683cbb0e841d','baseline':'21bd90ad34c048b08bc43e555eec98fa','injected':'3d536d1a8ab44eb7bb14941daa5271f3','injected_supplement':'b6a6a32fe3da5b81ba0fceb275ad7527'}
fingerprints={}
for label,rid in RUNS.items():
    rows=[dict(r) for r in db.execute('select * from events where run_id=? order by id',(rid,))]
    fingerprints[label]={'run_id':rid,'events':len(rows),'raw_payloads_sha256':sha(json.dumps(rows,ensure_ascii=False,separators=(',',':')).encode())}
    events=[{**r,'payload':json.loads(r['payload'])} for r in rows]
    save(f'sources/{label}/events.redacted.json',clean(events))
    for table in ['runs','planner_tasks','planner_task_attempts','task_work_items','task_work_attempts','run_units','findings','run_execution_state']:
        field='id' if table=='runs' else 'run_id'
        data=[unpack(r) for r in db.execute(f'select * from {table} where {field}=?',(rid,))]
        save(f'sources/{label}/{table}.redacted.json',clean(data))

prompts=[unpack(r) for r in db.execute('select * from prompts')]
save('sources/prompt_registry.redacted.json',clean(prompts))
prompt_search=[]
for name in ['secondorder','authz','state']:
    raw=(HERE.parent/f'e_materials_20261111/prompts/{name}.md').read_text(encoding='utf-8').strip()
    needles={'secondorder':['专攻「二次注入」','写入安全、读出危险'], 'authz':['专攻业务越权与隐性逻辑缺陷','身份来源 → 对象标识来源'], 'state':['专攻业务状态机与并发缺陷','读状态 → 校验 → 写状态']}[name]
    matches=[]
    for table,fields in [('prompts',['id','label','text']),('runs',['id','prompt_id','prompt_label','prompt_text','worker_strategy'])]:
        for row in db.execute(f'select {",".join(fields)} from {table}'):
            d=dict(row); text=' '.join(str(d.get(k) or '') for k in ['text','prompt_text','worker_strategy'])
            if any(n in text for n in needles) or raw in text:
                matches.append({'table':table,**{k:d[k] for k in fields if k not in ['text','prompt_text','worker_strategy']},'exact_text':raw in text,'needle_matches':[n for n in needles if n in text]})
    prompt_search.append({'name':name,'source_sha256':sha(raw.encode()),'needles':needles,'matches':matches})
save('sources/special_prompt_historical_search.json',prompt_search)
db.commit(); db.close()
save('sources/collection.json',{'started_at':started,'finished_at':dt.datetime.now(dt.timezone.utc).isoformat(),'database_mode':'SQLite URI mode=ro, one read transaction','runs':RUNS,'fingerprints':fingerprints,'redactions':dict(COUNTS),'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'model_requests':0,'database_mutations':0})
print(json.dumps({'runs':fingerprints,'historical_prompt_matches':{r['name']:len(r['matches']) for r in prompt_search}},ensure_ascii=False))
