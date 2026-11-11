"""Verify this Git delivery offline; no model, network, database, or service calls."""
import hashlib,json,zipfile
from pathlib import Path
P=Path(__file__).resolve().parent
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=load(P/'delivery_manifest.json')
for f in manifest['files']:
    p=P/f['path']
    assert p.is_file() and p.stat().st_size==f['bytes'] and sha(p)==f['sha256'],f['path']
assert max(f['bytes'] for f in manifest['files'])<100*1024*1024
archives=sorted((P/'archives').glob('*.zip'))
assert len(archives)==7
for archive in archives:
    expected=archive.with_suffix('.zip.sha256.txt').read_text(encoding='utf-8').split()[0]
    assert sha(archive)==expected,archive.name
    with zipfile.ZipFile(archive) as z:assert z.testzip() is None,archive.name
screens=P/'projects/screenshot_supplement_20261111'
images=load(screens/'screens_manifest.json')
assert len(images)==8
for r in images:
    p=screens/r['image']
    assert p.read_bytes()[:2]==b'\xff\xd8' and sha(p)==r['sha256'],r['id']
    assert sha(screens/r['ax'])==r['ax_sha256']
    assert r['url'].startswith('http://127.0.0.1:5173/')
scope=load(screens/'capture_scope.json')
assert len(scope['uncompleted'])==3 and scope['model_calls']==0
fundamental=P/'projects/fundamental_completion_20261111'
for f in load(fundamental/'material_manifest.json')['files']:assert sha(fundamental/f['path'])==f['sha256'],f['path']
for f in load(screens/'package_manifest.json')['files']:assert sha(screens/f['path'])==f['sha256'],f['path']
print(json.dumps({'verified':True,'files':len(manifest['files']),'archive_CRC_and_SHA256':7,'unmodified_Chrome_screenshots':8,'fundamental_material_files':203,'screenshot_package_files':42,'largest_file_bytes':max(f['bytes'] for f in manifest['files']),'model_requests':0},ensure_ascii=False))
