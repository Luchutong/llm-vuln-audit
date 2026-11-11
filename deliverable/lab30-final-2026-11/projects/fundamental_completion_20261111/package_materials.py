"""Build a bounded material archive after offline integrity and provenance verification."""
import datetime as dt,hashlib,json,shutil,subprocess,sys,zipfile
from pathlib import Path
P=Path(__file__).resolve().parent
for filename in ['《网络安全》大实验-团队分工与任务清单-v3.md','材料验收口径_漏洞发现能力_2026-11-11.md','《网络安全》大实验-基于LLM辅助的漏洞挖掘-项目实施计划书-v3.md']:
    shutil.copyfile(P.parent.parent/filename,P/'references'/filename)
include_dirs={'attribution','defense','defense_probe','prompt_units','references','sources','special_prompts'}
exclude_scripts={'inspect_sources.py','inspect_exported.py','inspect_api.py','inspect_transport.py'}
files=sorted(p for p in P.rglob('*') if p.is_file() and '__pycache__' not in p.parts and (p.relative_to(P).parts[0] in include_dirs or (p.parent==P and p.name not in exclude_scripts and (p.suffix=='.py' or p.name in {'README.md','completion_summary.json','model_usage_ledger.json'}))))
items=[{'path':p.relative_to(P).as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]
manifest={'created_at':dt.datetime.now(dt.timezone.utc).isoformat(),'files':items,'model_requests_in_packaging':0,'excluded':'inspection scratch files, __pycache__, archive/verification self references; no screenshots created in this batch'}
(P/'material_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
completed=subprocess.run([sys.executable,str(P/'verify_materials.py')],capture_output=True,text=True,encoding='utf-8')
print(completed.stdout,end='')
if completed.returncode:print(completed.stderr);raise SystemExit(completed.returncode)
# Compare against the already selected credential entirely in memory; never print it.
from load_local_model import selected_model
configuration,_=selected_model();key=configuration.api_key.encode()
if any(key in p.read_bytes() for p in files):raise RuntimeError('Credential detected in candidate evidence archive; packaging aborted')
target=P.parent/'三项关键材料补证包_2026-11-11.zip'
with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for p in files+[P/'material_manifest.json',P/'verification_result.json']:z.write(p,'fundamental_completion_20261111/'+p.relative_to(P).as_posix())
with zipfile.ZipFile(target) as z:
    if z.testzip() is not None:raise RuntimeError('Archive CRC failure')
checksum=hashlib.sha256(target.read_bytes()).hexdigest()
target.with_suffix('.zip.sha256.txt').write_text(checksum+'  '+target.name+'\n',encoding='utf-8')
receipt={'archive':str(target),'bytes':target.stat().st_size,'sha256':checksum,'manifest_files':len(items),'zip_crc_passed':True,'credential_values_in_archive':0,'model_requests_in_packaging':0}
(P/'package_receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(receipt,ensure_ascii=False))
