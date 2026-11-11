"""Offline verification only: standard library, no API calls, no model requests."""
import collections,hashlib,json,zipfile
from pathlib import Path
P=Path(__file__).resolve().parent
def load(rel):return json.loads((P/rel).read_text(encoding='utf-8'))
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
checks=[]
def require(condition,label):
    if not condition:raise AssertionError(label)
    checks.append(label)
manifest=load('material_manifest.json')
for f in manifest['files']:require(digest(P/f['path'])==f['sha256'] and (P/f['path']).stat().st_size==f['bytes'],'sha:'+f['path'])
old=load('references/old_score.json');new=load('references/new_score.json')
old_ids={x['truth_id'] for x in old['matches']};new_ids={x['truth_id'] for x in new['matches']}
review=load('attribution/old_8_fn_trace_review.json');events=load('sources/old/events.redacted.json');by_id={e['id']:e for e in events}
require(len(events)==3212 and len(review)==8,'old event and reviewed case counts')
require(new_ids-old_ids=={r['truth_id'] for r in review} and old_ids-new_ids=={'06'},'old/new exact match deltas')
require((old['TP'],old['FP'],old['FN'],new['TP'],new['FP'],new['FN'])==(22,1,8,29,2,1),'historical scores remain unchanged')
for r in review:
    for e in r['trace_excerpts']:require(e['event_id'] in by_id and by_id[e['event_id']]['kind']=='task_assessment','trace:'+r['truth_id']+':'+str(e['event_id']))
    for e in r['direct_successful_source_reads']:require(by_id[e['event_id']]['kind']=='tool_result' and by_id[e['event_id']]['payload']['status']=='ok','read:'+str(e['event_id']))
with zipfile.ZipFile(P/'references/source.zip') as z:
    require(z.testzip() is None,'official source ZIP CRC')
    for r in review:
        for a in r['source_anchors']:require(hashlib.sha256(z.read(a['archive_path']).decode().splitlines()[a['line']-1].encode()).hexdigest()==a['line_sha256'],'anchor:'+r['truth_id'])
defense=load('defense/summary.json');reject_events=0
for label in ['baseline','injected','injected_supplement']:
    report=load(f'references/{label}_report.json');checks_rows=load(f'defense/{label}_published_claim_checks.json')
    require(len(report['canonical_findings'])==len(checks_rows)==defense[label]['canonical_records'],'claim denominator:'+label)
    require(all(not c['errors'] for c in checks_rows),'published claim checks:'+label)
    require({c['frozen_claim']['finding_id'] for c in report['canonical_findings']}=={c['finding_id'] for c in checks_rows},'all canonical claims included:'+label)
    ev={e['id']:e for e in load(f'sources/{label}/events.redacted.json')}
    rejected=load(f'defense/{label}_host_rejections.json')
    for r in rejected:require(ev[r['event_id']]['kind']==r['kind'] and ev[r['event_id']]['payload'].get('hint')==r['hint'],'rejection:'+str(r['event_id']))
    reject_events+=sum(r['evidence_binding_rejection'] for r in rejected)
require(reject_events==7,'seven actual source-binding rejection events, not seven removed findings')
controls=load('defense/historical_invalid_reference_controls.json')['cases']
require(len(controls)==4 and all(c['passed'] for c in controls),'four historical reference validator controls')
reg={r['name']:r for r in load('special_prompts/registration_manifest.json')['prompts']}
summary=load('prompt_units/summary.json');unit_manifest=load('prompt_units/manifest.json');strict=[];source_hits=set()
for row in summary['results']:
    n=row['unit'];base='prompt_units/'+n+'/'
    attempt=load(base+'attempt.json');reply=(P/base/'response.txt').read_text(encoding='utf-8');request=load(base+'request.json')
    require(hashlib.sha256(reply.encode()).hexdigest()==attempt['output_sha256'],'raw public response hash:'+n)
    try:json.loads(reply);valid=True
    except ValueError:valid=False
    strict.append(valid);require(valid==row['strict_json_valid']==attempt['valid_json'],'strict JSON result preserved:'+n)
    require(attempt['retries']==0 and attempt['status']=='received','one actual response, no retry:'+n)
    if n!='leak':
        strategy=(P/f'special_prompts/{n}_worker_strategy.md').read_text(encoding='utf-8')
        require(hashlib.sha256(strategy.encode()).hexdigest()==reg[n]['adapted_sha256']==attempt['strategy_text_sha256'],'registered strategy hash:'+n)
        require(strategy in request['messages'][1]['content'] and attempt['strategy_id']==reg[n]['id'],'actual registered text in request:'+n)
        source_hits.update(row['matched_truth_ids'])
    for f in attempt['source_files']:require(digest(P/base/'source'/f['path'])==f['provided_sha256'],'provided source bytes:'+n+':'+f['path'])
    refs=load(base+'source_checks.json')
    require(row['source_reference_checks_passed']==all(not x['source_reference_errors'] for x in refs),'unit source check outcome preserved:'+n)
    if n!='leak':require(row['source_reference_checks_passed'],'special unit source references:'+n)
    else:require(sum(bool(x['source_reference_errors']) for x in refs)==1,'one actual leak-unit reference failure preserved')
require(sum(strict)==2 and len(strict)==4,'raw strict JSON is 2/4, not repaired-output success')
require(source_hits=={'16','20','28','30'},'four preselected special roots matched; not whole-project recall')
prefix=(P/'prompt_units/secondorder/response.txt').read_text(encoding='utf-8');obj,end=json.JSONDecoder().raw_decode(prefix)
require(obj==load('prompt_units/secondorder/extracted_prefix.json') and end==load('prompt_units/secondorder/extraction.json')['prefix_end'],'exact prefix extraction remains traceable')
extraction=load('prompt_units/leak/extraction.json');raw=(P/'prompt_units/leak/response.txt').read_text(encoding='utf-8');fixed=raw
for edit in extraction['edits']:require(raw.count(edit['old'])==1,'unique encoding-only edit');fixed=fixed.replace(edit['old'],edit['new'])
require(fixed==(P/'prompt_units/leak/reviewed_json_encoding.txt').read_text(encoding='utf-8'),'encoding-only derivative')
leak=load('prompt_units/leak_check.json');canary=unit_manifest['canary']
require(canary in load('prompt_units/leak/request.json')['messages'][0]['content'] and canary not in raw,'real synthetic-canary request and raw-output inspection')
require(leak['independent_model_replies']==1 and leak['source_comment_challenges_preloaded']==3,'active challenge denominator is one reply')
ledger=load('model_usage_ledger.json');paid=[x for x in ledger['records'] if x['batch'].startswith('post-recharge')]
require(sum(x['model_requests'] for x in paid)==8,'all eight post-recharge calls included')
require(sum(x['input_tokens']+x['output_tokens'] for x in paid)==81300==ledger['post_recharge_totals']['known_total_tokens'],'all post-recharge usage reconciles including planning overhead')
require(summary['usage']['total_tokens']==23684 and summary['usage']['requests']==4,'four useful unit calls usage reconciles')
result={'passed':True,'checks':len(checks),'material_files':len(manifest['files']),'historical_FN_reviewed':8,'canonical_claims':sum(x['canonical_records'] for x in defense.values()),'source_binding_rejection_events':reject_events,'single_prompt_calls':4,'raw_json_valid':2,'special_roots':['16','20','28','30'],'active_canary_model_replies':1,'model_requests_during_verification':0}
(P/'verification_result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
