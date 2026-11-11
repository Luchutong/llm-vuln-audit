"""Summarize bounded new measurements and their provenance, without further model calls."""
import datetime as dt,hashlib,json,shutil
from pathlib import Path
P=Path(__file__).resolve().parent
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def save(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
units=load(P/'prompt_units/summary.json');defense=load(P/'defense/summary.json');attribution=load(P/'attribution/summary.json')
registration=load(P/'special_prompts/registration_manifest.json')
for row in registration['prompts']:
    name=row['name'];raw=(P/f'special_prompts/{name}_original.md').read_bytes()
    row['original_text_sha256']=row.pop('original_sha256',row.get('original_text_sha256'))
    row['original_file_sha256']=hashlib.sha256(raw).hexdigest()
registration['hash_note']='original_text_sha256 excludes surrounding whitespace; original_file_sha256 hashes exact saved bytes; adapted_sha256 hashes exact strategy text including its final newline.'
save(P/'special_prompts/registration_manifest.json',registration)
rows=[]
initial=load(P/'special_prompts/latest_experiment.json')
for t in initial['trials']:
    a=t['attempts'][0];rows.append({'batch':'pre-recharge-402','id':a['run_id'],'model_requests':a['usage'].get('requests'),'input_tokens':a['usage'].get('input_tokens'),'output_tokens':a['usage'].get('output_tokens'),'total_tokens':a['usage'].get('total_tokens'),'valid_model_output':False,'stop_reason':a.get('stop_reason',{}).get('code')})
probe=load(P/'defense_probe/latest_bundle.json');pu=probe['run'].get('usage',{})
rows.append({'batch':'pre-recharge-402','id':probe['run']['id'],'model_requests':pu.get('requests'),'input_tokens':pu.get('input_tokens'),'output_tokens':pu.get('output_tokens'),'total_tokens':pu.get('total_tokens'),'valid_model_output':False,'stop_reason':'model_unavailable'})
minimal=load(P/'special_prompts/minimal/latest_experiment.json')
for t in minimal['trials']:
    a=t['attempts'][0];u=a.get('usage',{});rows.append({'batch':'post-recharge-planning-only','id':a['run_id'],'model_requests':u.get('requests'),'input_tokens':u.get('input_tokens'),'output_tokens':u.get('output_tokens'),'total_tokens':u.get('total_tokens'),'valid_special_worker_output':False,'stop_reason':a.get('stop_reason',{}).get('code')})
small=load(P/'defense_probe/minimal/latest_bundle.json');u=small['run'].get('usage',{})
rows.append({'batch':'post-recharge-planning-only','id':small['run']['id'],'model_requests':u.get('requests'),'input_tokens':u.get('input_tokens'),'output_tokens':u.get('output_tokens'),'total_tokens':u.get('total_tokens'),'valid_special_worker_output':False,'stop_reason':'insufficient_small_stage_budget'})
for r in units['results']:
    u=r['usage'];rows.append({'batch':'post-recharge-prompt-unit','id':r['unit_id'],'unit':r['unit'],'model_requests':1,'input_tokens':u['prompt_tokens'],'output_tokens':u['completion_tokens'],'total_tokens':u['total_tokens'],'received_public_model_output':True,'strict_json_valid':r['strict_json_valid']})
post=[r for r in rows if r['batch'].startswith('post-recharge')]
for row in post:
    row['derived_total_tokens']=row['input_tokens']+row['output_tokens'] if row.get('input_tokens') is not None and row.get('output_tokens') is not None else None
totals={'requests':sum(r.get('model_requests') or 0 for r in post),'known_input_tokens':sum(r.get('input_tokens') or 0 for r in post),'known_output_tokens':sum(r.get('output_tokens') or 0 for r in post),'known_total_tokens':sum(r.get('derived_total_tokens') or 0 for r in post),'complete_input_output_records':all(r.get('derived_total_tokens') is not None for r in post),'provider_total_field_records':sum(r.get('total_tokens') is not None for r in post),'price_not_estimated':True}
save(P/'model_usage_ledger.json',{'records':rows,'post_recharge_totals':totals,'unit_only_totals':units['usage'],'note':'Failed HTTP402 attempts retain missing usage as null. Planning-only calls are counted separately, not hidden in the four useful single-call units. No retries were executed.'})
runtime=Path(r'\\wsl.localhost\Ubuntu-24.04\home\luchitong\work\vuln-audit')
code={}
for name in ['backend/audit/config.py','backend/audit/worker_strategies.py','backend/audit/codemodel.py']:
    code[name]=hashlib.sha256((runtime/name).read_bytes()).hexdigest()
save(P/'sources/prompt_unit_runtime_code_identity.json',{'collected_at':dt.datetime.now(dt.timezone.utc).isoformat(),'files':code,'method':'Read existing WSL source through UNC, no backend edits/restart. Model secrets read only in process memory and never exported.','sqlite_config_read':'Checkpointed main DB via mode=ro&immutable=1, selected model and endpoint checked against live public API; credentials not copied.'})
for src,name in [('e_materials_20261111/四例专项契约与历史证据.md','historical_four_cases.md'),('poc_isolated_20261111/四例历史验证材料.json','historical_four_cases.json')]:
    target=P/'references'/name;shutil.copyfile(P.parent/src,target)
save(P/'completion_summary.json',{'attribution':'done: eight observed trace paths, scores unchanged, no causal ablation claim','defense':'done within declared scopes:78 canonical contracts, actual rejection ledger, public lexical checks, one new synthetic-canary Prompt unit; no universal no-impact claim','special_prompts':'done as new standalone Prompt-unit invocation: three registered versions, four exact source-root matches, original replies and encoding failures preserved. Historical E runs and production-worker invocation not recovered.','new_runtime_screenshots':'not_collected: Computer Use stopped because current Windows browser URL could not be reliably confirmed. No alternate capture or fabricated screenshot was substituted.','report_written':False,'post_recharge_usage':totals})
md=['# 三项关键材料补齐索引','','本批补材料，不编写最终报告；不修改历史冻结结果、原评分和归档ZIP。','',
'- [旧八项未匹配的实际轨迹复核](attribution/旧八项漏报轨迹复核.md)：旧轮3212条事件、逐项读取与判断记录、30项新旧对应。八项从旧未匹配变为新匹配，同时#06由旧匹配变为新类型未匹配；不把观察、相关定位、独立精确匹配混为一谈，不作单改动因果保证。',
'- [对抗输出补充核验](defense/对抗输出补充核验.md)：25+25+28条规范主张的结构/类型/CVSS/数据流检查均通过；327条响应元记录及108个发生过解析或结构/语义拒绝的响应单列，其中7个事件为源码证据绑定拒绝。公开输出词面检查附完整范围和规则。',
'- [三份专项与最小泄漏实际补证](prompt_units/专项与泄漏补证.md)：3份已注册策略对应3次实际单次模型请求，覆盖4例预先选择的源码根因；另有1次3处注释挑战的合成canary请求，原始公开回复未出现canary或所列宿主长句。三份策略原文、适配版、注册ID、请求体、源码SHA、响应ID/原文、逐项检查均保留。',
'',
'新增单次补证是预装源码的独立Prompt单元试验，未运行生产Planner/Worker和动态POC；不计入全量框架成绩。四例真实POC继续由历史作业支撑。原始回复严格JSON仅2/4通过，另两份分别保存有效前缀提取/编码转义修复，原文和失败结论不变。',
'',
'主动泄漏的有效单位是1次模型回复、同次3处载荷，不是3次独立试验；没有放入任何真实密钥。其结果仅支持本次合成标记挑战未观察到公开泄漏，不能证明注入对审计普遍无影响。',
'',
f"充值后全部模型调用共{totals['requests']}次、已知{totals['known_total_tokens']} tokens（含4次仅产生规划的框架轮次）；其中真正的四次单元补证为23,684 tokens。明细见 [用量台账](model_usage_ledger.json)，HTTP402失败批次另存、用量缺失保持null，无自动重试。",
'',
'新增截图未采集：Computer Use因无法可靠确认当前Windows浏览器网址停止。已有真实原图继续按原批次引用，本包未用渲染图替代原窗口截图。',
'',
'[历史四例原始验证材料](references/historical_four_cases.json)和[契约说明](references/historical_four_cases.md)是原件副本，不声称本次重新执行。`references/`保存本次复核所用输入与原结果；`sources/`保存只读导出及指纹。',
'',
'执行 `python verify_materials.py` 仅做离线校验，不调用模型。`run_prompt_units.py`会产生付费模型请求且默认拒绝重复已有attempt；无需为阅读/验收再次运行。']
(P/'README.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
print(json.dumps({'post_recharge_usage':totals,'completion':'material statements finalized'},ensure_ascii=False))
