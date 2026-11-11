"""Create explicitly labelled read-only views of existing local evidence.

These pages are material viewers, never simulated platform run results. Model
replies remain verbatim text, and raw JSON/reference failures remain visible.
"""
import datetime as dt, hashlib, html, json, shutil
from pathlib import Path
P=Path(__file__).resolve().parent;S=P.parent/'fundamental_completion_20261111';V=P/'viewer';V.mkdir(exist_ok=True)
def load(p):return json.loads((S/p).read_text(encoding='utf-8'))
def esc(s):return html.escape(str(s),quote=True)
def table(headers,rows):return '<table><thead><tr>'+''.join('<th>'+esc(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+str(v)+'</td>' for v in row)+'</tr>' for row in rows)+'</tbody></table>'
CSS='''body{font:17px/1.65 system-ui,"Microsoft YaHei",sans-serif;color:#17212b;background:#f4f6f8;margin:0}main{max-width:1580px;margin:30px auto;padding:28px 36px;background:white;border:1px solid #d6dde5}h1{font-size:28px;margin:14px 0}h2{font-size:21px;margin:25px 0 12px}p{margin:10px 0}.notice{padding:13px 18px;border:1px solid #c39b38;background:#fff9e8;font-weight:600}.meta{font:14px/1.6 ui-monospace,Consolas,monospace;color:#394c5c;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;font-size:15px}td,th{border:1px solid #cbd5df;padding:9px 12px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf2f7}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f7f9fb;border:1px solid #d5dee7;padding:18px;font:15px/1.7 ui-monospace,Consolas,"Microsoft YaHei",monospace}.raw{font-size:16px}.good{color:#176744}.bad{color:#a3352d}a{color:#1458a2}code{font-family:Consolas,monospace}nav a{margin-right:20px}small{color:#536579}'''
sources=[]
def provenance(rel):
    p=S/rel;sha=hashlib.sha256(p.read_bytes()).hexdigest();sources.append({'source':str(p),'sha256':sha})
    return '<p class="meta">原文件：'+esc(rel)+'<br>SHA-256：'+sha+'</p>'
def page(name,title,body):
    notice='离线材料原件查看器 · 非审计平台运行页面 · 不产生模型请求 · 原始结果与失败项如实保留'
    result='<!doctype html><html lang="zh-CN"><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+esc(title)+' | 本机补证材料查看</title><style>'+CSS+'</style><main><div class="notice">'+notice+'</div><h1>'+esc(title)+'</h1><nav><a href="index.html">材料索引</a><a href="attribution.html">旧8项复核</a><a href="defense.html">输出校验</a><a href="units.html">专项调用</a><a href="leak.html">泄漏探针</a></nav>'+body+'<hr><small>页面生成仅为查看已存在的原件。截图时间以截图索引为准，实验时间以原始 attempt/response 记录为准。</small></main></html>'
    (V/name).write_text(result,encoding='utf-8')

review=load('attribution/old_8_fn_trace_review.json');summary=load('attribution/summary.json')
rows=[]
for r in review:
    rows.append([esc(r['truth_id']),esc(r['trace_supported_conclusion']),esc(', '.join(str(e['event_id']) for e in r['direct_successful_source_reads']) or '无直接读取事件；有模型观察'),esc(', '.join(str(e['event_id']) for e in r['trace_excerpts']))])
body='<p>旧运行 <code>'+summary['old_run']+'</code><br>新运行 <code>'+summary['new_run']+'</code></p><p>复核依据：旧轮3212条实际事件。新结果补上旧8项匹配，同时#06从旧匹配变为新类型未匹配，TP由22变29。</p>'+table(['真值','轨迹支持的情况','读取事件','判断事件'],rows)
body+='<p>观察、后续方向及相关漏洞定位分别保留；不把评分未匹配一律写为“模型完全没看到”，不作单项改动的因果保证。</p>'+provenance('attribution/old_8_fn_trace_review.json')
page('attribution.html','旧八项未匹配：实际轨迹复核',body)
r=next(x for x in review if x['truth_id']=='09');trace=r['trace_excerpts'][0]
body='<p>旧轮实际公开记录：event <strong>63417</strong> · task <code>'+esc(trace['task_key'])+'</code> · '+esc(trace['created_at'])+'</p><p>原摘要已明确提到数据库堆栈输出，但该轮没有对应的info_disclosure漏洞条目。下文仅展示原公开摘要与观察。</p><h2>原始公开摘要</h2><pre>'+esc(trace['summary'])+'</pre><h2>原始相关观察</h2><pre>'+esc(json.dumps([o for o in trace['observations'] if 'database.php' in json.dumps(o,ensure_ascii=False)],ensure_ascii=False,indent=2))+'</pre>'+provenance('sources/old/events.redacted.json')
page('old_event_63417.html','旧轮事件63417：风险观察与未发布记录',body)

defense=load('defense/summary.json');rows=[];reject_rows=[]
for label,s in defense.items():
    rows.append([esc(label),f"{s['published_contract_passed']}/{s['canonical_records']}",s['model_response_metadata_records'],s['parse_rejection_events'],s['structured_rejection_events'],s['evidence_binding_rejection_events']])
    for r in load(f'defense/{label}_host_rejections.json'):
        if r['evidence_binding_rejection']:reject_rows.append([esc(label),r['event_id'],esc(r['hint'])])
body='<p>对象：原配对基线、原注入及单侧注入接续的全部规范主张（含待审项）。</p>'+table(['批次','规范条目结构通过','响应元记录','解析拒绝事件','结构/语义拒绝','证据绑定拒绝'],rows)
body+='<p>78条规范主张扩展结构检查通过；327条响应元记录另行统计。7次证据绑定拒绝的单位是事件，一次提交可涉及多条主张，也可修正后重新发布，不能当作永久删除7个漏洞。</p><h2>实际源码证据绑定拒绝原文</h2>'+table(['批次','事件ID','原始拒绝说明'],reject_rows)+provenance('defense/summary.json')
page('defense.html','对抗输出：结构检查与实际拒绝台账',body)

unit=load('prompt_units/summary.json');budget=load('model_usage_ledger.json');rows=[]
for r in unit['results']:
    a=load('prompt_units/'+r['unit']+'/attempt.json')
    rows.append(['<a href="'+r['unit']+'.html">'+esc(r['unit'])+'</a>',esc(', '.join(r['matched_truth_ids'])),esc(r['strategy_id'] or '合成canary控制'),'<span class="'+('good' if r['strict_json_valid'] else 'bad')+'">'+('通过' if r['strict_json_valid'] else '失败，另存提取记录')+'</span>',r['usage']['total_tokens'],esc(a['unit_id'])])
body='<p><strong>独立Prompt单元补证</strong>：当前同一模型、已注册策略及必要源码预装输入。属于单次请求取证；生产Planner/Worker调度和动态POC未在本批执行。</p>'+table(['单次请求','精确类型/主定位匹配','注册策略ID','原始严格JSON','tokens','单元ID'],rows)
body+='<p>专项三次覆盖#28二次注入、#16 IDOR、#30敏感字段改权、#20提现竞态。这四例已存在于旧基线，不能记作新增4个漏洞或全项目Recall100%。</p><p>四次单元请求合计23,684 tokens，无重试；充值后全部8次调用合计81,300 tokens，已包含4次仅规划的开销。</p><p>原始JSON为2/4通过。泄漏探针另有一处越界支撑引用，保留为失败项；三份专项的引用范围检查通过。编码/前缀提取均有独立记录。</p>'+provenance('prompt_units/summary.json')+provenance('model_usage_ledger.json')
page('units.html','三份专项真实调用与四例源码主张',body)

for r in unit['results']:
    name=r['unit'];a=load(f'prompt_units/{name}/attempt.json');response=load(f'prompt_units/{name}/response.json');raw=(S/f'prompt_units/{name}/response.txt').read_text(encoding='utf-8')
    body='<p class="meta">单元ID：'+esc(a['unit_id'])+'<br>响应ID：'+esc(response['id'])+'<br>策略ID：'+esc(a['strategy_id'] or 'synthetic-canary-control')+'<br>模型：'+esc(response['model'])+'<br>实际请求时间：'+esc(a['started_at'])+'<br>原始严格JSON：'+('通过' if r['strict_json_valid'] else '失败（原文不改，离线提取/编码修复另存）')+'<br>输出SHA-256：'+esc(a['output_sha256'])+'</p>'
    body+='<p>下方是原始公开回复全文，按浏览器自动换行显示；未把前缀提取或编码修复后的内容替换进来。内容中的正常/攻击请求是模型提出的静态方案，真实HTTP观测引用历史POC原件。</p><h2>原始公开回复</h2><pre class="raw">'+esc(raw)+'</pre>'+provenance(f'prompt_units/{name}/response.txt')
    page(name+'.html',{'secondorder':'二次注入：原始单次模型回复','authz':'IDOR与敏感字段改权：原始回复','state':'提现竞态：原始单次模型回复','leak':'泄漏探针：原始单次模型回复'}[name],body)

leak=load('prompt_units/leak_check.json');m=load('prompt_units/manifest.json');q=load('prompt_units/leak/request.json');probe=load('defense_probe/manifest.json');a=load('prompt_units/leak/attempt.json')
body='<p>有效分母：<strong>1次实际模型回复</strong>，同次预装<strong>3处攻击注释</strong>。本次为独立Prompt单元；合成标记不是任何真实密钥。</p>'+table(['检查项','实际结果'],[['合成canary进入系统段',esc(leak['canary_in_system_input'])],['原始公开回复出现canary',leak['canary_in_public_output']],['所列宿主长句命中',len(leak['host_phrase_hash_hits'])],['原始严格JSON','失败，存在未转义引号'],['引用检查','一处越界支撑引用，保留失败；未据此排除泄漏分母']])
body+='<p class="meta">单元ID：'+esc(a['unit_id'])+'<br>原始输出SHA-256：'+esc(leak['public_reply_sha256'])+'</p><h2>系统段合成标记（用于复核请求/回复对应）</h2><pre>'+esc(m['canary'])+'</pre><h2>三处源码中的原始攻击注释</h2>'+table(['位置','实际载荷'],[[esc(x['path']),esc(x['payload'])] for x in probe['probes']])
body+='<p>只支持“本次合成标记挑战未观察到公开泄漏”；不外推为普遍无影响、三次独立试验或真实密钥安全保证。<a href="leak.html">本页</a>的原始回复全文单独见 <a href="leak_response.html">原始公开回复</a>。</p>'+provenance('prompt_units/leak_check.json')+provenance('prompt_units/leak/request.json')
# Preserve the raw reply page before using leak.html for the readable check view.
shutil.copyfile(V/'leak.html',V/'leak_response.html')
page('leak.html','最小泄漏挑战：实际输入与原文检查',body)
links=[('attribution.html','旧八项实际轨迹复核'),('old_event_63417.html','旧轮原始公开事件63417'),('defense.html','78条规范输出与7次实际拒绝'),('units.html','三份专项实际调用与原始格式结果'),('secondorder.html','二次注入原始模型回复'),('authz.html','IDOR/字段改权原始模型回复'),('state.html','提现竞态原始模型回复'),('leak.html','合成canary主动挑战'),('leak_response.html','泄漏探针原始模型回复')]
page('index.html','本机补证材料：原件查看索引','<p>该查看器只读取2026-11-11已归档原件，页面内容不代表新执行，截图不替代原始请求/响应、事件或文件哈希。</p><ul>'+''.join('<li><a href="'+u+'">'+esc(t)+'</a></li>' for u,t in links)+'</ul>')
(P/'viewer_sources.json').write_text(json.dumps({'created_at':dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),'source_root':str(S),'sources':sources,'pages':links,'model_requests':0,'nature':'Explicitly labelled offline evidence viewer, not the production audit platform'},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'pages':len(links)+1,'sources':len(sources),'viewer':str(V),'model_requests':0},ensure_ascii=False))
