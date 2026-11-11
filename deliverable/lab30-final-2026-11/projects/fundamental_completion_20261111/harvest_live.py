"""Archive public API evidence for newly authorized runs; no model requests are made here."""
import datetime as dt,json,sys,urllib.error,urllib.parse,urllib.request
from pathlib import Path
P=Path(__file__).resolve().parent;API='http://127.0.0.1:8899'
def get(path):
    with urllib.request.urlopen(API+path,timeout=30) as r:return json.load(r)
def save(path,v):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
minimal='--minimal' in sys.argv
E=P/'special_prompts'/('minimal' if minimal else '');eid=json.loads((E/'experiment.json').read_text(encoding='utf-8'))['id']
ex=get(f'/api/prompt-experiments/{eid}');save(E/'latest_experiment.json',ex)
print(json.dumps({'experiment':eid,'status':ex.get('status'),'phase':ex.get('progress',{}).get('phase'),'trials':len(ex.get('trials',[]))},ensure_ascii=False))
for trial in ex.get('trials',[]):
    tid=trial['id'];out=E/'trials'/tid
    try:
        detail=get(f'/api/prompt-experiments/{eid}/trials/{tid}');save(out/'detail.json',detail)
        events=[];after=0
        while True:
            page=get(f'/api/prompt-experiments/{eid}/trials/{tid}/events?after={after}&limit=500')
            batch=page.get('events',[]) if isinstance(page,dict) else page
            if not batch:break
            events.extend(batch);after=batch[-1]['id']
            if len(batch)<500:break
        save(out/'events.json',events)
        state=trial.get('status') or detail.get('status')
        if state not in ['running','pending','queued']:
            try:save(out/'report.json',get(f'/api/prompt-experiments/{eid}/trials/{tid}/report?format=json'))
            except urllib.error.HTTPError as err:save(out/'report_unavailable.json',{'http_status':err.code,'message':err.read().decode()[:1200]})
        print(json.dumps({'trial':tid,'prompt_id':trial.get('prompt_id'),'state':state,'events':len(events),'attempts':[{'run_id':a.get('run_id'),'requests':a.get('usage',{}).get('requests'),'stop_reason':a.get('stop_reason'),'finding_count':a.get('finding_count')} for a in trial.get('attempts',[])]},ensure_ascii=False)[:1800])
    except urllib.error.HTTPError as err:print(json.dumps({'trial':tid,'http_status':err.code,'error':err.read().decode()[:400]},ensure_ascii=False))
D=P/'defense_probe'/('minimal' if minimal else '');r=json.loads((D/'run.json').read_text(encoding='utf-8'));rid=r.get('id') or r['run']['id']
bundle=get(f'/api/runs/{rid}');save(D/'latest_bundle.json',bundle)
events=[];after=0
while True:
    page=get(f'/api/runs/{rid}/event-log?after={after}');batch=page.get('events',[])
    if not batch:break
    events.extend(batch);after=batch[-1]['id']
    if len(batch)<2000:break
save(D/'events.json',events)
status=(bundle.get('run') or bundle).get('status')
if status not in ['pending','running','paused']:
    try:save(D/'report.json',get(f'/api/runs/{rid}/report?format=json'))
    except urllib.error.HTTPError as err:save(D/'report_unavailable.json',{'http_status':err.code,'message':err.read().decode()[:1200]})
print(json.dumps({'disclosure_probe_run':rid,'status':status,'events':len(events),'bundle_keys':list(bundle),'collected_at':dt.datetime.now(dt.timezone.utc).isoformat()},ensure_ascii=False))
