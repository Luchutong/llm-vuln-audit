"""Reconcile fixed scores with actual archived public audit traces, without altering results."""
import collections, datetime as dt, hashlib, json, zipfile
from pathlib import Path
P=Path(__file__).resolve().parent; BASE=P.parent/'closure_evidence_20261111'
OUT=P/'attribution';OUT.mkdir(exist_ok=True)
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def save(n,v):(OUT/n).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
events=load(P/'sources/old/events.redacted.json'); by_id={e['id']:e for e in events}
old=load(BASE/'scores/old.json');new=load(BASE/'scores/new.json')
anchors=load(BASE/'inputs/dataset/scoring_anchors_v2.json')['vulnerabilities']
amap={a['id']:a for a in anchors}
old_findings=load(BASE/'inputs/old/findings.json')
db_findings=load(P/'sources/old/findings.redacted.json')
old_ids={m['truth_id'] for m in old['matches']};new_ids={m['truth_id'] for m in new['matches']}
CASES=[
 ('07','formula.php',[63417],'读取并提出动态调用后续方向，未形成该根因的漏洞条目','deferred_risk','summary',None),
 ('09','database.php',[63417],'已在观察中指出异常堆栈暴露，未作为 info_disclosure 漏洞发布','risk_left_as_observation','observation','database.php 输出异常堆栈'),
 ('10','register.php',[63566],'已提及使用 MD5 存密码，但保留在注册/退出流程观察中','risk_left_as_observation','observation','register/logout 的会话处理'),
 ('14','settings.php',[63637,63935],'邮箱校验/参数化的安全观察未覆盖 CSRF；后续摘要虽提到无 CSRF 校验，仍未发布该漏洞','boundary_confusion_and_unpublished_risk','summary',None),
 ('17','users.php',[63637],'源码读取用于批量赋值后的权限影响说明，未见独立的客户端 Cookie 角色信任漏洞条目','independent_boundary_not_published','rationale',None),
 ('18','maintenance.php',[63417],'读取后把 maintenance 头鉴权列入剩余工作，未形成该根因的漏洞条目','deferred_risk','summary',None),
 ('23','member_lookup.php',[63185],'观察中指出 helper 的 SQL 拼接并视为另一方向，未形成跨文件 SQL 注入漏洞条目','deferred_cross_file_risk','observation','其他调用点均已参数化或使用固定 SQL'),
 ('24','host_check.php',[63417,63681],'已识别跨文件 shell_exec 拼接，但与 ping.php 命令注入按同根因表述；保留条目主定位为 ping.php:2，未命中独立 helper 真值','merged_distinct_location','observation','ping.php 与 batch-check.php 的 host 直接拼接 shell_exec'),
]
records=[]
with zipfile.ZipFile(BASE/'inputs/dataset/lab30-shop-1.0.0-source.zip') as z:
    for tid,filename,event_ids,conclusion,kind,field,obs_title in CASES:
        locs=amap[tid]['scoring_locations'];sources=[]
        for loc in locs:
            path='lab30-shop/'+loc['path'];raw=z.read(path);lines=raw.decode().splitlines()
            line=lines[loc['line']-1]
            assert hashlib.sha256(line.encode()).hexdigest()==loc['line_sha256']
            sources.append({**loc,'archive_path':path,'source_line':line})
        reads=[e for e in events if e['kind']=='tool_result' and e['payload'].get('status')=='ok' and e['payload'].get('tool')=='read_source' and str(e['payload'].get('args',{}).get('path','')).endswith('/'+filename)]
        excerpts=[]
        for eid in event_ids:
            e=by_id[eid];p=e['payload']
            item={'event_id':eid,'kind':e['kind'],'created_at':e['created_at'],'task_id':p.get('task_id'),'task_key':p.get('task_key'),'summary':p.get('summary'),'rationale':p.get('rationale'),'remaining_work':p.get('remaining_work'),'observations':p.get('observations')}
            excerpts.append(item)
        related=[{k:f.get(k) for k in ['id','title','vulnerability_type','primary_location','disposition','evidence','summary','propagation']} for f in db_findings if filename in json.dumps({k:f.get(k) for k in ['primary_location','evidence','summary','propagation']},ensure_ascii=False)]
        task_ids={e['payload'].get('task_id') for e in reads}|{e['task_id'] for e in excerpts}
        errors=[{'event_id':e['id'],'kind':e['kind'],'task_id':e['payload'].get('task_id'),'phase':e['payload'].get('phase'),'error_code':e['payload'].get('error_code'),'hint':e['payload'].get('hint')} for e in events if e['kind'] in ['agent_parse_error','agent_output_rejected'] and e['payload'].get('task_id') in task_ids]
        records.append({'truth_id':tid,'class':amap[tid]['class'],'old_protocol_match':tid in old_ids,'new_protocol_match':tid in new_ids,'classification':kind,'trace_supported_conclusion':conclusion,'source_anchors':sources,'direct_successful_source_reads':[{'event_id':e['id'],'created_at':e['created_at'],'args':e['payload'].get('args'),'task_id':e['payload'].get('task_id'),'task_key':e['payload'].get('task_key'),'preview':e['payload'].get('preview')} for e in reads],'trace_excerpts':excerpts,'related_collection_time_findings':related,'task_error_events_background_only':errors,'limits':'This explains the observed recording/matching path, not the internal psychological cause or a causal effect of any single framework change.'})
        assert tid not in old_ids and tid in new_ids
save('old_8_fn_trace_review.json',records)
comparison=[]
for a in anchors:
    tid=a['id'];comparison.append({'truth_id':tid,'class':a['class'],'old_match':tid in old_ids,'new_match':tid in new_ids,'old_finding_ids':[m['finding_id'] for m in old['matches'] if m['truth_id']==tid],'new_finding_ids':[m['finding_id'] for m in new['matches'] if m['truth_id']==tid]})
save('30_truth_comparison.json',comparison)
summary={'reviewed_at':dt.datetime.now(dt.timezone.utc).isoformat(),'reviewer':'Codex 对实际公开轨迹的离线复核；非成员人工签名','old_run':'2969bcf204cd43b5baf2683cbb0e841d','new_run':'3b50dbaf45955d989aacf47162e47967','old_FN':sorted(set(amap)-old_ids),'new_FN':sorted(set(amap)-new_ids),'gained':sorted(new_ids-old_ids),'lost':sorted(old_ids-new_ids),'source_event_count':len(events),'classification_counts':dict(collections.Counter(r['classification'] for r in records)),'causal_claim':False,'score_files_unchanged':True}
save('summary.json',summary)
md=['# 旧定稿八项未匹配的实际轨迹复核','','本次只读导出了旧轮3212条事件、工作项及条目，按冻结源码、真值和原评分逐项复核；不更改旧分数，也不追加人工发现到旧结果。复核者为Codex，未伪造成员签名。','', '| 真值 | 轨迹支持的情况 | 直接读取事件 | 判断记录事件 |','| --- | --- | --- | --- |']
for r in records:
    md.append(f"| {r['truth_id']} | {r['trace_supported_conclusion']} | {', '.join(str(x['event_id']) for x in r['direct_successful_source_reads']) or '未找到直接 read_source 事件；存在模型观察提及'} | {', '.join(str(x['event_id']) for x in r['trace_excerpts'])} |")
md+=['','逐条原始公开摘要、观察、读取请求及响应摘录、源码锚点和SHA见 [复核JSON](old_8_fn_trace_review.json)。其中#23不能据缺少直接读取事件就断言模型从未见过源码：其观察已经提到helper拼接，其他上下文提供路径仍可能存在。#24的相关发现不等于满足独立主定位真值。','','新旧对照：旧八项未匹配在新结果中均匹配，但旧已匹配的#06在新结果中未匹配。因此TP从22变29，是新增8项匹配、减少1项匹配；新#06在同一模板预览位置已有LFI主张，严格协议要求RFI，属于类型未匹配，不能写成完全未发现该入口。','','这份材料支持“观察、后续方向、独立主定位到最终条目的转化存在差异”。新轮含历史结果复用、接续和operator补证，不能把增益归因于某一个改动，也不构成等预算独立盲测。每个任务的解析/拒绝事件只作为背景保留，没有证据将某次拒绝认定为某个漏报的直接原因。','', '完整30项对照见 [对照表](30_truth_comparison.json)，旧原评分和新原评分保持原值。']
(OUT/'旧八项漏报轨迹复核.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
print(json.dumps(summary,ensure_ascii=False))
