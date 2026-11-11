"""Register faithful host-contract adaptations and execute a new, isolated evidence batch.

This supplements missing invocation provenance; it does not recreate E's historical run.
"""
import datetime as dt, hashlib, json, urllib.error, urllib.request
from pathlib import Path
P=Path(__file__).resolve().parent
OUT=P/'special_prompts'; OUT.mkdir(exist_ok=True)
API='http://127.0.0.1:8899'
def save(name,v): (OUT/name).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def request(path,body=None):
    req=urllib.request.Request(API+path,data=None if body is None else json.dumps(body,ensure_ascii=False).encode(),headers={} if body is None else {'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=30) as r:return json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f'HTTP {e.code}: {e.read().decode()}') from e
if (OUT/'experiment.json').exists(): raise SystemExit('Experiment already recorded; do not duplicate model requests.')
registered=[]
for name,label in [('secondorder','二次注入'),('authz','对象及字段越权'),('state','状态并发')]:
    record_path=OUT/f'{name}_registration.json'
    original=(P.parent/f'e_materials_20261111/prompts/{name}.md').read_text(encoding='utf-8').strip()
    # Preserve analysis rules verbatim. Replace the historical output section only,
    # because modern Worker strategies cannot replace the production output contract.
    body=original.split('# 四、输出格式')[0].rstrip()
    if name=='secondorder':body=body.replace('结论只能取 candidate / no_candidate / insufficient_context 三者之一。','结论按本次宿主协议发布；candidate / no_candidate / insufficient_context 仅为历史概念，不作为当前输出枚举。')
    adapted=body+'\n\n# 四、本次宿主输出适配\n\n本策略只指导源码分析，最终输出严格遵守宿主当前结构化协议。确认风险时通过 findings 交付实际已读 evidence、vulnerability_type、primary_location 与简短依据；无证据或缺上下文时如实记录，不伪造发现。正常/攻击方案作为静态复核说明，当前 poc_mode=off，不声称执行过验证。二次注入保留写入与读出证据；越权保留身份、对象或敏感字段与缺失授权证据；并发保留读取、检查、写入及幂等边界证据。\n'
    (OUT/f'{name}_original.md').write_text(original+'\n',encoding='utf-8')
    (OUT/f'{name}_worker_strategy.md').write_text(adapted,encoding='utf-8')
    if record_path.exists():row=json.loads(record_path.read_text(encoding='utf-8'))
    else:
        row=request('/api/prompts',{'label':f'E接续补证20261111：{label}','text':adapted,'reason':'新批次专项Prompt调用取证；前三节来自E文稿，输出部分适配现行Worker宿主协议，不冒称历史原批次。','kind':'worker_strategy','contract_version':'worker-strategy-v1','issues':['仅取证专项策略实际调用，不以单轮局部检出率推断策略优劣。']})
        save(f'{name}_registration.json',row)
    assert row['text']==adapted
    registered.append({'name':name,'id':row['id'],'label':row['label'],'original_sha256':hashlib.sha256(original.encode()).hexdigest(),'adapted_sha256':hashlib.sha256(adapted.encode()).hexdigest(),'registered_at':row.get('created_at')})
save('registration_manifest.json',{'batch':'new supplemental invocation experiment','created_at':dt.datetime.now(dt.timezone.utc).isoformat(),'prompts':registered,'historical_search':'../sources/special_prompt_historical_search.json','adaptation':'Original sections 1-3 preserved except legacy outcome enum; section 4 adapted to current host contract. No benchmark truth or target locations added.'})
payload={'protocol':'lab30-full-v2','prompt_ids':['worker-w2-v2']+[r['id'] for r in registered],'baseline_prompt_id':'worker-w2-v2','repeats':1,'run_limits':{'responses':96,'tools':600,'seconds':240},'experiment_wall_seconds':7200}
save('experiment_request.json',payload)
row=request('/api/prompt-experiments',payload)
save('experiment.json',row)
print(json.dumps({'experiment_id':row.get('id'),'status':row.get('status'),'registered_prompts':registered,'limits':payload['run_limits']},ensure_ascii=False))
