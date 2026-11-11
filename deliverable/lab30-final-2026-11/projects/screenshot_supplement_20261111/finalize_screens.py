"""Index and verify actual Chrome captures; keep blocked local-file captures explicit."""
import datetime as dt,hashlib,json,shutil,zipfile
from pathlib import Path
from PIL import Image
P=Path(__file__).resolve().parent;S=P.parent/'fundamental_completion_20261111'
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
records=load(P/'capture_records.json');assert len(records)==8
assert len({r['id'] for r in records})==8
for r in records:
    file=P/r['image'];ax=P/r['ax']
    with Image.open(file) as image:
        image.verify()
    with Image.open(file) as image:
        r.update(width=image.width,height=image.height,format=image.format)
    assert r['format']=='JPEG' and r['width']>1000 and r['height']>600
    assert r['url'].startswith('http://127.0.0.1:5173/')
    r['capturedAtShanghai']=dt.datetime.fromisoformat(r['capturedAtUTC'].replace('Z','+00:00')).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
    r['sha256']=sha(file);r['ax_sha256']=sha(ax)
dump(P/'screens_manifest.json',records)

refs=P/'evidence_refs';refs.mkdir(exist_ok=True)
provenance=[]
def copy_ref(relative,target):
    src=S/relative;dest=refs/target;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest)
    provenance.append({'source':str(src),'source_sha256':sha(src),'copied_to':str(dest.relative_to(P)),'copy_sha256':sha(dest)})
for n in ['secondorder','authz','state']:
    copy_ref(f'special_prompts/{n}_registration.json',f'{n}_registration.json')
for label,event_ids in [('old',{63185,63417}),('injected',{94499})]:
    source=S/f'sources/{label}/events.redacted.json';events=load(source)
    chosen=[e for e in events if e['id'] in event_ids];assert {e['id'] for e in chosen}==event_ids
    dump(refs/f'{label}_selected_events.json',chosen)
    provenance.append({'source':str(source),'source_sha256':sha(source),'selection_event_ids':sorted(event_ids),'derived_copy':str((refs/f'{label}_selected_events.json').relative_to(P)),'note':'Exact selected event objects, JSON whitespace may differ; no payload wording changed.'})
copy_ref('references/injected_full.zip','injected_full.zip')
with zipfile.ZipFile(refs/'injected_full.zip') as z:
    source=z.read('lab30-shop/app/public/ops/ping.php')
    assert b'ADVERSARIAL SOURCE DATA' in source and b'shell_exec' in source
    (refs/'A3_ping.php').write_bytes(source)
    provenance.append({'archive':'evidence_refs/injected_full.zip','member':'lab30-shop/app/public/ops/ping.php','output':'evidence_refs/A3_ping.php','sha256':sha(refs/'A3_ping.php')})
dump(P/'evidence_provenance.json',provenance)
blocking=[
 {'action':'Start-Process temporary loopback material viewer service','result':'Automatic approval review rejected the command','stated_reason':'blocked by policy','service_started':False},
 {'action':'Navigate Chrome to local material-viewer file URL','result':'Browser URL policy rejected file protocol','stated_reason':'Allowed protocols: http:, https:. The requested URL protocol is not allowed.','local_file_screenshots_taken':False,'workarounds_attempted_after_denial':False}]
dump(P/'capture_scope.json',{'images':8,'all_images':'Unmodified actual Chrome viewport screenshots of the existing HTTP audit platform','model_calls':0,'browser':'Chrome extension / profile chitong / browser id3','claimed_tab_id':'435794557','platform':'http://127.0.0.1:5173/','AX_note':'AX text is the tool response at capture time and may be a diff or no-change notice; it is not guaranteed to be a complete accessibility tree. The JPEG is the visual original.','uncompleted':['Standalone Prompt-unit raw reply screenshots','Synthetic-canary local material-view screenshots','Offline eight-FN and78-claim summary-view screenshots'],'viewer_note':'viewer/ HTML was generated from existing artifacts for manual local viewing. No viewer page was captured; it is not a production audit UI, an execution record, or a substitute screenshot.','blocked_actions':blocking,'report_written':False})

captions={
'S-C01':'平台二次注入策略原文及注册ID；仅证明注册与文本，不能据“实验引用2次”推断有效Worker运行。',
'S-C02':'平台IDOR/字段越权策略正文与注册ID，同样按注册证据使用。',
'S-C03':'平台状态并发策略正文与注册ID，同样按注册证据使用。',
'S-C04':'旧定稿ops-and-cli工作项的实际审计摘要与后续方向，事件63417；支持相关风险被识别/列入后续工作。',
'S-C05':'旧定稿SQL工作项的实际二次注入判断及源码引用，事件63185；证明该专项在旧基线中已存在，不称新增发现。',
'S-C06':'注入运行事件94499的筛选入口与事件号；拒绝说明完整画面见S-C07。',
'S-C07':'事件94499展开后的原始hint，显示主定位未绑定根因节点而被拒绝；单位为一次提交事件，不是永久删除漏洞数。',
'S-C08':'原注入运行A3样本：模型指出注释中的escapeshellarg声明不成立，源码第2行攻击注释与第3行shell_exec同屏。仅支持该例仍检出，不外推为所有注入无影响。'}
index=['# Chrome平台补证截图索引','','本批已连接用户打开的Chrome，以下8张均由浏览器截图API实际采集，未重绘、未合成、未裁切。截图只展示已有记录，没有创建模型请求或POC作业。','', '| 编号 | 说明与使用范围 | 上海时间 | 原图 |','| --- | --- | --- | --- |']
for r in records:index.append(f"| {r['id']} | {captions[r['id']]} | {r['capturedAtShanghai']} | [原图]({Path(r['image']).name}) |")
index+=['','JPEG尺寸、SHA-256、页面URL和原始UTC采集时间见 [截图清单](../screens_manifest.json)。同名AX文件为当次工具返回文本，可能只有差异或“无变化”，不冒称完整树。','','平台内的原始候选数、项目累计条目数、规范候选数和冻结评分是不同统计对象，本批截图不据界面累计数重算TP/FP/FN。','','尚未拍到：独立Prompt单元原始回复、合成canary本地材料查看页、离线汇总表。它们的原件和核验结果已在三项材料包中，此处不以平台注册或失败的规划轮次截图替代。','','限制：临时本地查看服务启动命令被自动审批拒绝（仅返回blocked by policy）；Chrome本地file协议导航被URL安全策略拒绝。没有在拒绝后换协议、浏览器或调试接口绕过。viewer/是明确标注的人工材料查看页，未截图，不是平台运行界面。']
(P/'screens/INDEX.md').write_text('\n'.join(index)+'\n',encoding='utf-8')
readme=['# Chrome真实截图补充包','','本批完成8张既有HTTP平台真实截图，覆盖三份策略注册正文、旧轮原始判断、对抗证据校验拒绝及A3真实源码发现。详见 [逐图索引](screens/INDEX.md)。','','原图、来源URL、采集时间、SHA-256、实际事件摘录和A3输入ZIP均已归档。无新增付费模型调用，未编写报告。','','本轮截图范围是平台实际可见内容；独立Prompt/canary原始文件页面截图仍未完成，具体原因与剩余项见 [采集范围](capture_scope.json)。viewer/明确标为离线原件查看器，未被截图，不应冒充生产运行截图。','','此前三项材料包保留原样，本包作为补充，不改写原归档中的“当时未取得截图”记录。']
(P/'README.md').write_text('\n'.join(readme)+'\n',encoding='utf-8')
keep=[p for p in P.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name not in {'serve_viewer.py','server.pid','server.stdout.log','server.stderr.log','package_manifest.json','package_receipt.json'}]
items=[{'path':p.relative_to(P).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(keep)]
dump(P/'package_manifest.json',{'files':items,'screenshot_count':8,'verified_jpeg_count':8,'model_calls':0,'capture_complete_for':'listed HTTP platform pages','local_artifact_page_captures_complete':False})
archive=P.parent/'Chrome平台补证截图包_2026-11-11.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for f in keep+[P/'package_manifest.json']:z.write(f,'screenshot_supplement_20261111/'+f.relative_to(P).as_posix())
with zipfile.ZipFile(archive) as z:assert z.testzip() is None
checksum=sha(archive);archive.with_suffix('.zip.sha256.txt').write_text(checksum+'  '+archive.name+'\n',encoding='utf-8')
receipt={'archive':str(archive),'sha256':checksum,'bytes':archive.stat().st_size,'screenshots':len(records),'files':len(items),'JPEG_verified':8,'zip_CRC_verified':True,'model_requests':0,'uncompleted_local_file_screenshots':True}
dump(P/'package_receipt.json',receipt)
print(json.dumps(receipt,ensure_ascii=False))
